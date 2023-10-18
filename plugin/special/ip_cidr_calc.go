package special

import (
	"fmt"
	"net"
)

func calcTest() {
	startIP := "1.0.0.0"
	endIP := "1.0.0.255"

	ipRange, err := calculateIPRange(startIP, endIP)
	if err != nil {
		fmt.Println("错误：", err)
	} else {
		fmt.Printf("IP范围：%s\n", ipRange)
	}
}

func calculateIPRange(startIP, endIP string) (string, error) {
	ipStart := net.ParseIP(startIP)
	ipEnd := net.ParseIP(endIP)

	if ipStart == nil || ipEnd == nil {
		return "", fmt.Errorf("无效的IP地址")
	}

	if ipStart.To4() == nil || ipEnd.To4() == nil {
		return "", fmt.Errorf("仅支持IPv4地址")
	}

	// 计算CIDR表示法
	ones, _ := ipStart.DefaultMask().Size()
	ipRange := fmt.Sprintf("%s/%d", ipStart.String(), ones)
	return ipRange, nil
}
