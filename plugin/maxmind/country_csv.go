package maxmind

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/Loyalsoldier/geoip/lib"
)

const (
	typeCountryCSV = "maxmindGeoLite2CountryCSV"
	descCountryCSV = "Convert MaxMind GeoLite2 country CSV data to other formats"
)

var (
	defaultCCFile   = filepath.Join("./", "geolite2", "GeoLite2-Country-Locations-en.csv")
	defaultIPv4File = filepath.Join("./", "geolite2", "GeoLite2-Country-Blocks-IPv4.csv")
	defaultIPv6File = filepath.Join("./", "geolite2", "GeoLite2-Country-Blocks-IPv6.csv")
)

func init() {
	lib.RegisterInputConfigCreator(typeCountryCSV, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return newGeoLite2CountryCSV(action, data)
	})
	lib.RegisterInputConverter(typeCountryCSV, &geoLite2CountryCSV{
		Description: descCountryCSV,
	})
}

func newGeoLite2CountryCSV(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
	var tmp struct {
		CountryCodeFile string     `json:"country"`
		IPv4File        string     `json:"ipv4"`
		IPv6File        string     `json:"ipv6"`
		IPInfoFile      string     `json:"ipinfo"`
		Want            []string   `json:"wantedList"`
		OnlyIPType      lib.IPType `json:"onlyIPType"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, err
		}
	}

	if tmp.CountryCodeFile == "" {
		tmp.CountryCodeFile = defaultCCFile
	}

	if tmp.IPv4File == "" {
		tmp.IPv4File = defaultIPv4File
	}

	if tmp.IPv6File == "" {
		tmp.IPv6File = defaultIPv6File
	}

	return &geoLite2CountryCSV{
		Type:            typeCountryCSV,
		Action:          action,
		Description:     descCountryCSV,
		CountryCodeFile: tmp.CountryCodeFile,
		IPv4File:        tmp.IPv4File,
		IPv6File:        tmp.IPv6File,
		IPInfoFile:      tmp.IPInfoFile,
		Want:            tmp.Want,
		OnlyIPType:      tmp.OnlyIPType,
	}, nil
}

type geoLite2CountryCSV struct {
	Type            string
	Action          lib.Action
	Description     string
	CountryCodeFile string
	IPv4File        string
	IPv6File        string
	IPInfoFile      string
	Want            []string
	OnlyIPType      lib.IPType
}

func (g *geoLite2CountryCSV) GetType() string {
	return g.Type
}

func (g *geoLite2CountryCSV) GetAction() lib.Action {
	return g.Action
}

func (g *geoLite2CountryCSV) GetDescription() string {
	return g.Description
}

func (g *geoLite2CountryCSV) Input(container lib.Container) (lib.Container, error) {
	ccMap, err := g.getCountryCode()
	if err != nil {
		return nil, err
	}

	entries := make(map[string]*lib.Entry)

	if g.IPInfoFile != "" {
		if err := g.processIPInfo(g.IPInfoFile, entries); err != nil {
			return nil, err
		}
	} else {
		if g.IPv4File != "" {
			if err := g.process(g.IPv4File, ccMap, entries); err != nil {
				return nil, err
			}
		}

		if g.IPv6File != "" {
			if err := g.process(g.IPv6File, ccMap, entries); err != nil {
				return nil, err
			}
		}
	}

	var ignoreIPType lib.IgnoreIPOption
	switch g.OnlyIPType {
	case lib.IPv4:
		ignoreIPType = lib.IgnoreIPv6
	case lib.IPv6:
		ignoreIPType = lib.IgnoreIPv4
	}

	for name, entry := range entries {
		switch g.Action {
		case lib.ActionAdd:
			if err := container.Add(entry, ignoreIPType); err != nil {
				return nil, err
			}
		case lib.ActionRemove:
			container.Remove(name, ignoreIPType)
		default:
			return nil, lib.ErrUnknownAction
		}
	}

	return container, nil
}

func (g *geoLite2CountryCSV) getCountryCode() (map[string]string, error) {
	ccReader, err := os.Open(g.CountryCodeFile)
	if err != nil {
		return nil, err
	}
	defer ccReader.Close()

	reader := csv.NewReader(ccReader)
	lines, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	ccMap := make(map[string]string)
	for _, line := range lines[1:] {
		id := strings.TrimSpace(line[0])
		countryCode := strings.TrimSpace(line[4])
		if id == "" || countryCode == "" {
			continue
		}
		ccMap[id] = strings.ToUpper(countryCode)
	}
	return ccMap, nil
}

func (g *geoLite2CountryCSV) IpRangeToCIDR(start, end string) ([]string, error) {
	ips, err := netip.ParseAddr(start)
	if err != nil {
		return nil, err
	}
	ipe, err := netip.ParseAddr(end)
	if err != nil {
		return nil, err
	}

	isV4 := ips.Is4()
	if isV4 != ipe.Is4() {
		return nil, errors.New("start and end types are different")
	}
	if ips.Compare(ipe) > 0 {
		return nil, errors.New("start > end")
	}

	var (
		ipsInt = new(big.Int).SetBytes(ips.AsSlice())
		ipeInt = new(big.Int).SetBytes(ipe.AsSlice())
		nextIp = new(big.Int)
		maxBit = new(big.Int)
		cmpSh  = new(big.Int)
		bits   = new(big.Int)
		mask   = new(big.Int)
		one    = big.NewInt(1)
		buf    []byte
		cidr   []string
		bitSh  uint
	)
	if isV4 {
		maxBit.SetUint64(32)
		buf = make([]byte, 4)
	} else {
		maxBit.SetUint64(128)
		buf = make([]byte, 16)
	}

	for {
		bits.SetUint64(1)
		mask.SetUint64(1)
		for bits.Cmp(maxBit) < 0 {
			nextIp.Or(ipsInt, mask)

			bitSh = uint(bits.Uint64())
			cmpSh.Lsh(cmpSh.Rsh(ipsInt, bitSh), bitSh)
			if (nextIp.Cmp(ipeInt) > 0) || (cmpSh.Cmp(ipsInt) != 0) {
				bits.Sub(bits, one)
				mask.Rsh(mask, 1)
				break
			}
			bits.Add(bits, one)
			mask.Add(mask.Lsh(mask, 1), one)
		}

		addr, _ := netip.AddrFromSlice(ipsInt.FillBytes(buf))
		cidr = append(cidr, addr.String()+"/"+bits.Sub(maxBit, bits).String())

		if nextIp.Or(ipsInt, mask); nextIp.Cmp(ipeInt) >= 0 {
			break
		}
		ipsInt.Add(nextIp, one)
	}
	return cidr, nil
}

func (g *geoLite2CountryCSV) process(file string, ccMap map[string]string, entries map[string]*lib.Entry) error {
	if len(ccMap) == 0 {
		return errors.New("country code list must be specified")
	}
	if entries == nil {
		entries = make(map[string]*lib.Entry)
	}

	fReader, err := os.Open(file)
	if err != nil {
		return err
	}
	defer fReader.Close()

	reader := csv.NewReader(fReader)
	lines, err := reader.ReadAll()
	if err != nil {
		return err
	}

	// Filter want list
	wantList := make(map[string]bool)
	for _, want := range g.Want {
		if want = strings.ToUpper(strings.TrimSpace(want)); want != "" {
			wantList[want] = true
		}
	}

	for _, line := range lines[1:] {
		ccID := strings.TrimSpace(line[1])
		if countryCode, found := ccMap[ccID]; found {
			if len(wantList) > 0 {
				if _, found := wantList[countryCode]; !found {
					continue
				}
			}
			cidrStr := strings.ToLower(strings.TrimSpace(line[0]))
			entry, found := entries[countryCode]
			if !found {
				entry = lib.NewEntry(countryCode)
			}
			if err := entry.AddPrefix(cidrStr); err != nil {
				return err
			}
			entries[countryCode] = entry
		}
	}

	return nil
}

func (g *geoLite2CountryCSV) processIPInfo(file string, entries map[string]*lib.Entry) error {
	if entries == nil {
		entries = make(map[string]*lib.Entry)
	}

	fReader, err := os.Open(file)
	if err != nil {
		return err
	}
	defer fReader.Close()

	reader := csv.NewReader(fReader)
	lines, err := reader.ReadAll()
	if err != nil {
		return err
	}

	// Filter want list
	wantList := make(map[string]bool)
	for _, want := range g.Want {
		if want = strings.ToUpper(strings.TrimSpace(want)); want != "" {
			wantList[want] = true
		}
	}

	for _, line := range lines[1:] {
		countryCode := strings.TrimSpace(line[2])
		if len(wantList) > 0 {
			if _, found := wantList[countryCode]; !found {
				continue
			}
		}
		start_ip := strings.TrimSpace(line[0])
		end_ip := strings.TrimSpace(line[1])
		cidrStrList, _ := g.IpRangeToCIDR(start_ip, end_ip)
		entry, found := entries[countryCode]
		if !found {
			entry = lib.NewEntry(countryCode)
		}
		for _, cidrStr := range cidrStrList[:] {
			if err := entry.AddPrefix(cidrStr); err != nil {
				return err
			}
			entries[countryCode] = entry
		}

	}

	return nil
}
