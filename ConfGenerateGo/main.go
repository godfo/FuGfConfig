package main

import (
	"ConfGenerateGo/pkg/model"
	"ConfGenerateGo/pkg/util"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// loon data file path
// var loonInboxRulesUrl = [...]string{
// 	"https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Advertising/Advertising.list",
// 	"https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Advertising/Advertising.list"}

func main() {
	println("开始")

	// fmt.Println("是否要更新 or 下载远程数据 (y or n)")
	// var input string
	// // fmt.Scanln(&input)
	// input = "y"
	// // input = "n"
	// if input == "y" || input == "Y" {
	// 	downloadFiles()
	// }

	var base, inbox, inboxResult []string
	var ans []model.Pair

	//names := []string{"CodeTools"}
	names := []string{"Direct", "Proxy", "CodeTools", "Tracker", "FuckGarbageFeature", "FuckRogueSoftware"}
	for _, name := range names {
		//  清空残留的数据
		base, inbox, inboxResult = []string{}, []string{}, []string{}
		ans = []model.Pair{}
		fmt.Println("----开始处理 ", name, " ----")
		// 拼接文件路径
		buildString := func(ss ...string) string {
			var builder strings.Builder
			for _, s := range ss {
				builder.WriteString(s)
			}
			return builder.String()
		}
		base, inbox = readRule(buildString("../ConfigFile/DataFile/", name, "/", name, ".txt"), buildString("../ConfigFile/DataFile/", name, "/inbox.txt"))
		ans, inboxResult = policyProcessing(base, inbox)
		util.WriteFile("QuantumultXRules", ans, name, buildString("../ConfigFile/QuantumultX/", name, "Rules.conf"), true)
		util.WriteFile("LoonRule", ans, name, buildString("../ConfigFile/Loon/LoonRemoteRule/", name, "Rules.conf"), true)
		util.WriteFile("Host", ans, name, buildString("../ConfigFile/Host/", name, "Rules.conf"), true)
		util.WriteFile("DomainSetRule", ans, name, buildString("../ConfigFile/DomainSet/", name, "Rules.conf"), true)
		util.WriteFile("AdGuardHome", ans, name, buildString("../ConfigFile/AdGuardHome/", name, "Rules.conf"), true)
		util.WriteFile("Clash", ans, name, buildString("../ConfigFile/Clash/", name, "Rules.conf"), true)
		if len(inboxResult) != 0 {
			sort.Strings(inboxResult)
			util.NormalWriteFile(inboxResult, buildString("../ConfigFile/DataFile/", name, "/inbox.txt"))
		}
	}

	println("处理完成")
	println("结束")
}

func readRule(baseFilePath string, inboxFilePath string) ([]string, []string) {
	//
	var base, inbox []string
	// 读取 base
	// 判断文件是否存在
	_, err := os.Stat(baseFilePath)
	if err == nil {
		base = util.ReadFile(baseFilePath)
	} else {
		fmt.Println("发生错误:", err)
	}

	// 读取 inbox
	_, err = os.Stat(inboxFilePath)
	if err == nil {
		inbox = util.ReadFile(inboxFilePath)
	} else {
		//fmt.Println(err)
	}

	return base, inbox
}

func policyProcessing(base []string, inbox []string) ([]model.Pair, []string) {
	// map 来存取数据 key 是唯一的 放置域名或者 ip，value 放置规则

	// 构建 base map
	var ansMap = make(map[string]string)
	for _, v := range base {
		v = util.FormatCorrection(v)
		a := ""
		if strings.Count(v, ",") >= 1 {
			a, v = splitRule(v)
			ansMap[v] = a
		} else if isIPV4(v) {
			ansMap[v] = "IP-CIDR"
		} else if isIPV6(v) {
			ansMap[v] = "IP-CIDR6"
		} else if util.IsDomainRule(v) {
			if strings.HasPrefix(v, ".") {
				v = strings.TrimPrefix(v, ".")
				ansMap[v] = "DOMAIN-SUFFIX"
			} else {
				ansMap[v] = "DOMAIN"
			}
		} else {
			fmt.Println("发现未匹配到的规则，规则为：" + v)
			if strings.HasPrefix(v, ".") {
				v = strings.TrimPrefix(v, ".")
				ansMap[v] = "DOMAIN-SUFFIX"
			} else {
				ansMap[v] = "DOMAIN"
			}
		}
	}

	fmt.Println("规则基础库构建完成，共:", len(ansMap), "条规则")

	// 遍历 inbox
	var inboxResult []string
	if len(inbox) > 0 {
		for _, v := range inbox {
			v = util.CleanAll(v)
			// a := ""
			// flagIsSuffix := false
			// if strings.Count(v, ",") >= 1 {
			// 	a, v = splitRule(v)
			// } else if strings.HasPrefix(v, ".") {
			// 	// flagIsSuffix = true
			// 	v = strings.TrimPrefix(v, ".")
			// }
			if _, ok := ansMap[v]; !ok {
				// 如果不存在
				if util.IsDomainRule(v) {
					// 如果是 domain 规则
					count := strings.Count(v, ".") - 1
					flag := false
					s := v
					for i := 0; i < count; i++ {
						// fmt.Println("s: " + s)
						s = domainRuleIntercept(s)
						if _, ok := ansMap[s]; ok {
							// 如果命中，直接 break
							// fmt.Println("已存在: " + v)
							flag = true
							break
						}
					}
					if !flag {
						inboxResult = append(inboxResult, v)
						// if flagIsSuffix {
						// 	ansMap[v] = "DOMAIN-SUFFIX"
						// } else {
						// 	ansMap[v] = "DOMAIN"
						// }
					}
				} else {
					// ansMap[v] = a
					inboxResult = append(inboxResult, v)
				}
			}
		}
	}

	fmt.Println("查重后未处理的规则还剩 ", len(inboxResult), " 条")

	var data model.Pairs
	for k, v := range ansMap {
		data = append(data, model.Pair{Key: k, Value: v})
	}
	sort.Sort(sort.Reverse(data))

	fmt.Println("排序处理完后的规则共: ", len(data), " 条")

	return data, inboxResult
}

// 对 规则进行切片，返回中间
func splitRule(s string) (string, string) {
	ss := strings.Split(s, ",")
	if len(ss) >= 2 {
		return ss[0], ss[1]
	}
	return "", ""
}

// 对域名规则按 "." 切片
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

// 错误处理函数
func handleError(fn func() error) {
	if err := fn(); err != nil {
		fmt.Printf("error occurred: %v\n", err)
	}
}