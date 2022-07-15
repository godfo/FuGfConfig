package file

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

func ReadFile(filePath string) []string {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("open file err:", err)
		return nil
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	var ans []string
	for {
		str, err := reader.ReadString('\n')
		if err != nil || io.EOF == err {
			break
		}
		// fmt.Println(str)
		ans = append(ans, str)
	}
	return ans
}
