package main

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net"
    "strings"
    "net/http"
    "os"
    "sync"
    "time"
)

const (
    port = 12345
    version = "1.0.0-web"
)

type Request struct {
    Domain      string   `json:"domain"`
    DNSServers  []string `json:"dns_servers"`
    QueryType   string   `json:"query_type"`
}

type Result struct {
    Server       string  `json:"server"`
    QueryTime    string  `json:"querytime"`
    IP           string  `json:"ip"`
    TCPingTime   string  `json:"tcping"`
    Error        string  `json:"error,omitempty"`
}

var (
    dnsList   = []string{"119.29.29.29", "202.103.224.68", "223.5.5.5"}
    listMutex = &sync.Mutex{}
    fileMutex = &sync.Mutex{}
)

func main() {
    loadDNSList()
    http.HandleFunc("/dns-check", handler)
    http.HandleFunc("/add-dns", addDNSHandler)
    http.HandleFunc("/remove-dns", removeDNSHandler)
    http.Handle("/", http.FileServer(http.Dir("./static")))
    http.HandleFunc("/get-dns-list", getDNSListHandler)
    
    log.Printf("Starting web server on :%d", port)
    log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}

// 修改后的handler函数，按JSON文件中DNS服务器顺序排序结果
    func handler(w http.ResponseWriter, r *http.Request) {
        if len(dnsList) == 0 {
            http.Error(w, "DNS服务器列表为空，请先添加DNS服务器", http.StatusBadRequest)
            return
        }

        w.Header().Set("Access-Control-Allow-Origin", "*")
        
        var req Request
        body, err := io.ReadAll(r.Body)
        if err != nil {
            log.Printf("读取请求体失败: %v", err)
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        log.Printf("请求体内容: %s", string(body))
        log.Printf("请求头信息: %+v", r.Header)
        if err := json.Unmarshal(body, &req); err != nil {
            log.Printf("请求参数解析失败: %v", err)
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        log.Printf("成功解析请求参数: %+v", req)

        results := make(map[string]Result)
        resultChan := make(chan Result, len(req.DNSServers))
        
        for _, server := range req.DNSServers {
            go func(srv string) {
                // 调用原有逻辑（需要稍作调整）
                var result Result
                start := time.Now()
                ip, err := lookupIP(req.Domain, srv, getRecordType(req.QueryType))
                duration := time.Since(start)
                
                result.Server = srv
                if err != nil {
                    result.Error = err.Error()
                    resultChan <- result
                    return
                }
                
                result.QueryTime = duration.String()
                result.IP = ip
                
                pingDuration, err := tcping(ip, 80)
                if err != nil {
                    result.TCPingTime = "超时"
                    result.Error = err.Error()
                } else {
                    result.TCPingTime = fmt.Sprintf("%.2fms", float64(pingDuration)/float64(time.Millisecond))
                }
                
                resultChan <- result
            }(server)
        }

        // 收集所有结果到map中
        for i := 0; i < len(req.DNSServers); i++ {
            result := <-resultChan
            results[result.Server] = result
        }

        // 按JSON文件中DNS服务器顺序排序结果
        var response []Result
        for _, server := range dnsList {
            if result, ok := results[server]; ok {
                response = append(response, result)
            }
        }

        // 确保所有结果都被编码成JSON返回给前端
        log.Printf("返回响应内容: %+v", response)
        json.NewEncoder(w).Encode(response)
    }

    func loadDNSList() {
        file, err := os.Open("dns_servers.json")
        if err != nil {
            log.Printf("无法打开dns_servers.json文件: %v", err)
            return
        }
        defer file.Close()

        data, err := io.ReadAll(file)
        if err != nil {
            log.Printf("读取dns_servers.json文件失败: %v", err)
            return
        }

        log.Printf("成功读取dns_servers.json文件")
        log.Printf("文件内容: %s", string(data))
        json.Unmarshal(data, &dnsList)
        log.Printf("当前DNS服务器列表: %v", dnsList)
    }

    // 新增的DNS服务器管理handler
    func addDNSHandler(w http.ResponseWriter, r *http.Request) {
        server := r.URL.Query().Get("server")
        if net.ParseIP(server) == nil {
            http.Error(w, "Invalid IP address", http.StatusBadRequest)
            return
        }

        listMutex.Lock()
        defer listMutex.Unlock()
        dnsList = append(dnsList, server)
        saveDNSList()
    }

    func removeDNSHandler(w http.ResponseWriter, r *http.Request) {
        servers := r.URL.Query()["server"]
        
        listMutex.Lock()
        defer listMutex.Unlock()
        
        // 创建新的过滤后列表
        filtered := make([]string, 0, len(dnsList))
        for _, s := range dnsList {
            keep := true
            for _, toRemove := range servers {
                if s == toRemove {
                    keep = false
                    break
                }
            }
            if keep {
                filtered = append(filtered, s)
            }
        }
        dnsList = filtered
        saveDNSList()
    }

    // 保存结果到文件
    func saveResult(result Result) {
        fileMutex.Lock()
        defer fileMutex.Unlock()
        
        file, err := os.OpenFile("results.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
            log.Printf("无法打开日志文件: %v", err)
            return
        }
        defer file.Close()
        
        logEntry := fmt.Sprintf("[%s] %s - %s\n", 
            time.Now().Format(time.RFC3339), 
            result.Server, 
            result.IP)
        if _, err = file.WriteString(logEntry); err != nil {
            log.Printf("写入日志失败: %v", err)
        }
    }

func getDNSListHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    json.NewEncoder(w).Encode(dnsList)
}

func saveDNSList() {
    data, err := json.Marshal(dnsList)
    if err != nil {
        log.Printf("JSON编码失败: %v", err)
        return
    }
    
    if err := os.WriteFile("dns_servers.json", data, 0644); err != nil {
        log.Printf("写入DNS列表失败: %v", err)
    }
}

func lookupIP(domain string, dnsServer string, recordType uint16) (string, error) {
    // 创建自定义的DNS解析器
    r := &net.Resolver{
        PreferGo: true,
        Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
            d := net.Dialer{}
            return d.DialContext(ctx, network, fmt.Sprintf("%s:53", dnsServer))
        },
    }
    // 使用自定义解析器进行查询
    ips, err := r.LookupIPAddr(context.Background(), domain)
    if err != nil {
        return "", err
    }
    for _, ip := range ips {
        if ip.IP.To4() != nil || recordType == 28 && ip.IP.To16() != nil {
            return ip.IP.String(), nil
        }
    }
    return "", fmt.Errorf("no valid IP found")
}

func tcping(ip string, port int) (time.Duration, error) {
    var totalDuration time.Duration
    var successCount int
    const attempts = 5
    for i := 0; i < attempts; i++ {
        start := time.Now()
        host := ip
        if strings.Contains(ip, ":") {
            host = fmt.Sprintf("[%s]", ip)
        }
        conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 3*time.Second)
        if err == nil {
            conn.Close()
            totalDuration += time.Since(start)
            successCount++
        }
    }
    if successCount == 0 {
        return 0, fmt.Errorf("all attempts failed")
    }
    return totalDuration / time.Duration(successCount), nil
}

func getRecordType(queryType string) uint16 {
    switch queryType {
    case "4":
        return 1
    case "6":
        return 28  // AAAA record type
    default:
        return 1   // Default to A record
    }
}

func getNetworkType(recordType uint16) string {
    if recordType == 28 {
        return "ip6"
    }
    return "ip4"
}
