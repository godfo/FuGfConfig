package main

import (
	"ConfGenerateGo/file"
	"ConfGenerateGo/pkg/model"
	"ConfGenerateGo/pkg/util"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// loon data file path
var loonInboxRulesUrl = [...]string{
	"https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Advertising/Advertising.list",
	"https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Advertising/Advertising.list"}

var loonInboxRulesFilePath = [...]string{
	"../ConfigFile/Loon/LoonRemoteRule/Advertising/AdRulesBeta.conf",
	"./DataFile/inbox/loon/loon_inbox1.txt"}

var loonBaseRulesFilePath = [...]string{
	"../ConfigFile/Loon/LoonRemoteRule/Advertising/AdRules.conf",
	"./DataFile/loon_base.txt"}

const loonFuckRogueSoftwareHost = "../ConfigFile/Loon/LoonPlugin/FuckRogueSoftware.plugin"

const loonFuckRogueSoftwareRule = "../ConfigFile/Loon/LoonRemoteRule/FuckRogueSoftware.conf"

const surfboardFuckRogueSoftware = "../ConfigFile/Surfboard/FuckRogueSoftware.conf"

// qx data file path
const qxFuckRogueSoftware = "../ConfigFile/QuantumultX/FuckRogueSoftware.conf"

const fuckRogueSoftwareHost = "../ConfigFile/Hosts/FuckRogueSoftware.txt"

// agh data file path
const aghFuckRogueSoftware = "../ConfigFile/AdGuardHome/FuckRogueSoftware.txt"

const aghInboxRulesUrls = "../ConfigFile/AdGuardHome/待整合的规则.txt"

const aghInboxRulesFilePath = "./DataFile/inbox/agh/"

func main() {
	println("开始")

	// FuckRogueSoftware
	base, inbox := readRule("../ConfigFile/DataFile/RulesFile/RejectRulesFile/FuckRogueSoftware.txt")
	ans := policyProcessing(base, inbox)
	// loon FuckRogueSoftware.plugin
	util.WriteFile("LoonHost", ans, "FuckRogueSoftware", "../ConfigFile/Loon/LoonPlugin/FuckRogueSoftware.plugin", true)
	util.WriteFile("LoonRule", ans, "FuckRogueSoftware", "../ConfigFile/Loon/LoonRemoteRule/FuckRogueSoftware.conf", true)
	// domain set
	// util.WriteFile("DomainSetRule", ans, "FuckRogueSoftware", "../ConfigFile/DataFile/RulesFile/RejectRulesFile/DomainSet.txt", true)
	// QuantumultX Rules
	util.WriteFile("QuantumultXRules", ans, "FuckRogueSoftware", "../ConfigFile/QuantumultX/FuckRogueSoftware.conf", true)

	// FuckGarbageFeature
	base, inbox = readRule("../ConfigFile/DataFile/RulesFile/RejectRulesFile/FuckGarbageFeature.txt")
	ans = policyProcessing(base, inbox)
	util.WriteFile("QuantumultXRules", ans, "FuckGarbageFeature", "../ConfigFile/QuantumultX/FuckGarbageFeature.conf", true)

	// fmt.Println("是否要更新 or 下载远程数据 (y or n)")
	// var input string
	// // fmt.Scanln(&input)
	// input = "y"
	// // input = "n"
	// if input == "y" || input == "Y" {
	// 	downloadFiles()
	// }

	println("处理完成")
	println("结束")
}

func readRule(baseFilePath string) ([]string, []string) {
	var base, inbox []string
	// 读取 base
	base = util.ReadFile(baseFilePath)
	// 读取 inbox
	return base, inbox
}

func policyProcessing(base []string, inbox []string) []model.Pair {
	// map 来存取数据 key 是唯一的 放置域名或者ip，value放置规则

	// 构建 base map
	var ansMap = make(map[string](string))
	for _, v := range base {
		v = util.FormatCorrection(v)
		a := ""
		if strings.Count(v, ",") >= 1 {
			a, v = splitRule(v)
			ansMap[v] = a
		} else if isDomainRule(v) {
			if strings.HasPrefix(v, ".") {
				v = strings.TrimPrefix(v, ".")
				ansMap[v] = "DOMAIN-SUFFIX"
			} else {
				ansMap[v] = "DOMAIN"
			}
		} else if isIPV4(v) {
			ansMap[v] = "IP-CIDR"
		} else if isIPV6(v) {
			ansMap[v] = "IP-CIDR6"
		} else {
			fmt.Println("发现未匹配到的规则，规则为：" + v)
			ansMap[v] = "DOMAIN"
		}
	}

	fmt.Println("规则基础库构建完成，共:", len(ansMap), "条规则")

	fmt.Println("test")

	// 遍历 inbox
	if len(inbox) > 0 {
		for _, v := range inbox {
			v = util.FormatCorrection(v)
			a := ""
			flagIsSuffix := false
			if strings.Count(v, ",") >= 1 {
				a, v = splitRule(v)
			} else if strings.HasPrefix(v, ".") {
				flagIsSuffix = true
				v = strings.TrimPrefix(v, ".")
			}
			if _, ok := ansMap[v]; !ok {
				// 如果不存在
				if isDomainRule(v) {
					// 如果是 domain 规则
					count := strings.Count(v, ".") - 1
					flag := false
					s := v
					for i := 0; i < count; i++ {
						s = domainRuleIntercept(s)
						if _, ok := ansMap[s]; ok {
							// 如果命中，直接 break
							flag = true
							break
						}
					}
					if !flag {
						if flagIsSuffix {
							ansMap[v] = "DOMAIN-SUFFIX"
						} else {
							ansMap[v] = "DOMAIN"
						}
					}
				} else {
					ansMap[v] = a
				}
			}
		}
	}

	var data model.Pairs
	for k, v := range ansMap {
		data = append(data, model.Pair{Key: k, Value: v})
	}
	sort.Sort(sort.Reverse(data))

	fmt.Println("排序处理完后的规则共: ", len(data), " 条")

	return data
}

func downloadFiles() {
	file.DownloadFile(loonInboxRulesUrl[0], loonBaseRulesFilePath[1])
	file.DownloadFile(loonInboxRulesUrl[1], loonInboxRulesFilePath[1])

	var ans = file.ReadFile(aghInboxRulesUrls)
	for i := 0; i < len(ans); i++ {
		file.DownloadFile(ans[i], fmt.Sprint("%s%d.txt", aghInboxRulesFilePath, i))
	}
	println("更新远程数据完成")
}

func splitRule(s string) (string, string) {
	// 对 规则进行切片，返回中间
	ss := strings.Split(s, ",")
	if len(ss) >= 2 {
		return ss[0], ss[1]
	}
	return "", ""
}

func domainRuleIntercept(s string) string {
	firstInd := strings.Index(s, ".")
	return s[firstInd+1:]
}

func isIPV4(s string) bool {
	// 判断是否为 IPV4
	ipv4Pattern := regexp.MustCompile(`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	return ipv4Pattern.MatchString(s)
}

func isIPV6(s string) bool {
	// 判断是否为 IPV6
	ipv6Pattern := regexp.MustCompile(`^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$`)
	return ipv6Pattern.MatchString(s)
}

func isDomainRule(s string) bool {
	domainPattern := regexp.MustCompile(`^[a-zA-Z0-9\-\.]+(\.[a-zA-Z]{2,3}){1,2}(/\S*)?$`)
	return domainPattern.MatchString(s)
}
