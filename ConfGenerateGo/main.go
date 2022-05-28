package main

import (
	"ConfGenerateGo/file_operations"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var loonInboxRulesUrl = [...]string{
	"https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Advertising/Advertising.list",
	"https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Advertising/Advertising.list"}

var loonInboxRulesFilePath = [...]string{
	"../ConfigFile/Loon/LoonRemoteRule/Advertising/AdRulesBeta.conf",
	"./DataFile/inbox/loon/loon_inbox1.txt"}

var loonBaseRulesFilePath = [...]string{
	"../ConfigFile/Loon/LoonRemoteRule/Advertising/AdRules.conf",
	"./DataFile/loon_base.txt"}

const aghInboxRulesUrls = "../ConfigFile/AdGuardHome/待整合的规则.txt"

const aghInboxRulesFilePath = "./DataFile/inbox/agh/"

var aghBaseRulesFilePath = [...]string{
	"../ConfigFile/AdGuardHome/FuGfBlokList.txt"}

var loonRulesMap = make(map[string]string)

type void struct{}

var member void
var aghRulesSet = make(map[string]void)

func main() {
	println("开始")
	fmt.Println("是否要更新 or 下载远程数据 (y or n)")
	var input string
	// fmt.Scanln(&input)
	input = "y"
	// input = "n"
	if input == "y" || input == "Y" {
		downloadFiles()
	}

	// 处理文件
	//规则分为三个部分
	//匹配类型 ，匹配关键字，策略名称
	//MatchType MatchingKeywords PolicyName
	policyProcessing("REJECT")
	println("处理完成")
	println("结束")
}

// policy processing
func policyProcessing(policyName string) {
	// 循环读取文件 构建 base map
	for i := 0; i < len(loonBaseRulesFilePath); i++ {
		var ans = file_operations.ReadFile(loonBaseRulesFilePath[i])
		fmt.Println("base map", i, "共", len(ans), "条数据")
		// 遍历得到的数据
		for _, v := range ans {
			if isNote(v) {
				continue
			}
			v = formatCorrection(v)

			if (strings.Count(v, "DOMAIN") > 0 && strings.Count(v, ",") >= 1) ||
				(strings.Count(v, "IP-CIDR") > 0 || strings.Count(v, "IP-CIDR6") > 0) ||
				(strings.Count(v, "USER-AGENT") > 0 && strings.Count(v, ",") >= 1) {
				// 如果包含 DOMAIN 或者 IP 或者 USER-AGENT
				var data = strings.Split(v, ",")
				loonRulesMap[data[1]] = data[0]

				if strings.Count(v, "DOMAIN") > 0 {
					// 如果包含 DOMAIN
					aghRulesSet[data[1]] = member
				}
			} else {
				loonRulesMap[v] = "DOMAIN"
			}
		}
	}

	fmt.Println("Loon 规则基础数据库构建完成，共", len(loonRulesMap), "条数据")
	fmt.Println("AdguardHome 规则基础数据库构建完成，共", len(aghRulesSet), "条数据")

	// 循环读取待处理的数据文件
	var data []string
	for i := 0; i < len(loonInboxRulesFilePath); i++ {
		var ans = file_operations.ReadFile(loonInboxRulesFilePath[i])
		fmt.Println("读取待处理数据", i, ",共", len(ans), "条数据")
		for _, v := range ans {
			if isNote(v) {
				continue
			}
			v = formatCorrection(v)
			if v == "" {
				continue
			}
			var str string
			if strings.Contains(v, ",") {
				var a = strings.Split(v, ",")
				if _, ok := loonRulesMap[a[1]]; !ok {
					b1 := []string{a[0], a[1]}
					// b1 := []string{a[0], a[1], policyName}
					b2 := []string{a[0], a[1], "no-resolve"}
					if strings.Contains(v, "IP-CIDR") || strings.Contains(v, "IP-CIDR6") {
						str = strings.Join(b2, ",")
					} else {
						str = strings.Join(b1, ",")
					}
					loonRulesMap[a[1]] = a[0]
				}
			} else {
				// 仅域名或 IP
				if _, ok := loonRulesMap[v]; !ok {
					// if isIPV4(v) || isIPV6(v) {
					if isIPV4(v) {
						b := []string{"IP-CIDR", v}
						// b := []string{"IP-CIDR", v, policyName}
						str = strings.Join(b, ",")
						loonRulesMap[v] = "IP-CIDR"
					} else {
						b := []string{"DOMAIN-SUFFIX", v}
						// b := []string{"DOMAIN-SUFFIX", v, policyName}
						str = strings.Join(b, ",")
						loonRulesMap[v] = "DOMAIN-SUFFIX"
						aghRulesSet[v] = member
					}
				}
			}
			if str != "" {
				data = append(data, str)
			}
		}
	}

	fmt.Println("处理后共有 ", len(data), " 条 new 数据")

	// 新数据与老数据合并
	var ans = file_operations.ReadFile(loonBaseRulesFilePath[1])
	data = append(data, ans...)

	// 数据结果排序
	sort.Strings(data)

	fmt.Println("更新后去广告规则共有 ", len(data))
	// 写入文件
	file_operations.WriteFile(data, "./DataFile/ans.txt")
	file_operations.WriteFile(data, loonBaseRulesFilePath[1])
	file_operations.WriteClashFile(data, "./DataFile/ans1.txt")
	file_operations.WriteClashFile(data, "../ConfigFile/Clash/AdRules.txt")
	// file_operations.WriteClashFile(data, "../ConfigFile/AdGuardHome/FuGfBlokList.txt")
	//清除 betaAd 规则
	var ans1 []string
	ans1 = append(ans1, data[0])
	file_operations.WriteFile(ans1, "./DataFile/inbox.txt")
	file_operations.WriteFile(ans1, loonInboxRulesFilePath[0])
}

func downloadFiles() {
	file_operations.DownloadFile(loonInboxRulesUrl[0], loonBaseRulesFilePath[1])
	file_operations.DownloadFile(loonInboxRulesUrl[1], loonInboxRulesFilePath[1])

	var ans = file_operations.ReadFile(aghInboxRulesUrls)
	for i := 0; i < len(ans); i++ {
		file_operations.DownloadFile(ans[i], fmt.Sprint("%s%d.txt", aghInboxRulesFilePath, i))
	}
	println("更新远程数据完成")
}

// 规则格式统一
func formatCorrection(s string) string {
	s = strings.TrimPrefix(s, ".")
	s = strings.Replace(s, "\r", "", -1)
	s = strings.Replace(s, "\n", "", -1)
	s = strings.Replace(s, " ", "", -1)
	s = strings.Replace(s, "HOST", "DOMAIN", 1)
	s = strings.Replace(s, "host", "DOMAIN", 1)
	s = strings.Replace(s, "domain", "DOMAIN", 1)
	s = strings.Replace(s, "DOMAIN-suffix", "DOMAIN-SUFFIX", 1)
	s = strings.Replace(s, "IP6-CIDR", "IP-CIDR6", 1)
	s = strings.Replace(s, "ip6-cidr", "IP-CIDR6", 1)
	s = strings.Replace(s, "ip-cidr6", "IP-CIDR6", 1)
	s = strings.Replace(s, "ip-cidr,", "IP-CIDR", 1)
	s = strings.Replace(s, "USER-agent,", "USER-AGENT", 1)
	s = strings.Replace(s, "user-agent,", "USER-AGENT", 1)
	s = strings.Replace(s, "user-AGENT,", "USER-AGENT", 1)

	return s
}

func isNote(s string) bool {
	// 忽略注释与 URL-REGEX 规则和空行
	if strings.HasPrefix(s, "#") ||
		strings.HasPrefix(s, ";") ||
		strings.HasPrefix(s, "\n") ||
		strings.HasPrefix(s, "//") ||
		strings.HasPrefix(s, "!") ||
		strings.Contains(s, "URL-REGEX") {
		return true
	}
	return false
}

func isIPV4(s string) bool {
	// 判断是否为 IPV4
	partIp := "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
	grammer := partIp + "\\." + partIp + "\\." + partIp + "\\." + partIp
	matchMe := regexp.MustCompile(grammer)

	return matchMe.MatchString(s)
}

func isIPV6(s string) bool {
	//不可用
	// 判断是否为 IPV6
	partIp := "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
	grammer := partIp + "\\." + partIp + "\\." + partIp + "\\." + partIp
	matchMe := regexp.MustCompile(grammer)

	return matchMe.MatchString(s)
}

// func getDomain(s string) string {
// 	s = s[1:2]

// 	return s
// }
