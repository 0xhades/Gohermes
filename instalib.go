package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Pallinder/go-randomdata"
	"github.com/google/uuid"
)

type API struct {
	VERSION      string
	KeyVersion   string
	KEY          string
	CAPABILITIES string
}

type HttpResponse struct {
	Err                 error
	ResStatus           int
	Req                 *http.Request
	Res                 *http.Response
	Body                string
	Headers             http.Header
	Cookies             []*http.Cookie
	RequestSizeByBytes  float64
	ResponseSizeByBytes float64
}

func MakeHttpResponse(Response *http.Response, Request *http.Request, Error error, RequestSizeByBytes float64, ResponseSizeByBytes float64) HttpResponse {

	var res = ""
	var StatusCode = 0
	var Headers http.Header = nil
	var cookies []*http.Cookie = nil
	var err error

	if Error != nil {
		err = Error
	}
	if Response != nil {
		cookies = Response.Cookies()
		var reader io.ReadCloser
		switch Response.Header.Get("Content-Encoding") {
		case "gzip":
			reader, _ = gzip.NewReader(Response.Body)
			defer reader.Close()
		default:
			reader = Response.Body
		}
		body, _ := ioutil.ReadAll(reader)
		res = string(body)

		if Response.Header != nil {
			Headers = Response.Header
		}

		if Response.StatusCode != 0 {
			StatusCode = Response.StatusCode
		}
	}

	return HttpResponse{ResStatus: StatusCode, Res: Response, ResponseSizeByBytes: ResponseSizeByBytes, Req: Request, RequestSizeByBytes: RequestSizeByBytes, Body: res, Headers: Headers, Cookies: cookies, Err: err}
}

func createKeyValuePairs(m http.Header) string {
	b := new(bytes.Buffer)
	for key, value := range m {
		_, _ = fmt.Fprintf(b, "%s=\"%s\"\n", key, value)
	}
	return b.String()
}

func HMACSHA256(message string, key string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

func GetAPI() API { // random choise

	IG_VERSION := "107.0.0.27.121"
	IG_SIG_KEY := "c36436a942ea1dbb40d7f2d7d45280a620d991ce8c62fb4ce600f0a048c32c11"
	SIG_KEY_VERSION := "4"
	X_IG_Capabilities := "3brTvw=="

	_API := API{VERSION: IG_VERSION, KEY: IG_SIG_KEY, KeyVersion: SIG_KEY_VERSION, CAPABILITIES: X_IG_Capabilities}

	return _API
}

func accountCreateWEBCheck(us string, csrftoken string, proxy string, timeout int) (int, string, int, error) {

	data := "username=" + us + "&email=anadoctor3lawyalhsay69%40gmail.com&first_name=NoOne&opt_into_one_tap=false&enc_password=#PWD_INSTAGRAM_BROWSER:0:1589682409:d"

	var req *http.Request
	req, _ = http.NewRequest("POST", "https://www.instagram.com/accounts/web_create_ajax/attempt/", bytes.NewBuffer([]byte(data)))

	req.Header.Set("Origin", "https//www.instagram.com")
	req.Header.Set("X-Instagram-AJAX", "a546c5cc0f70")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:76.0) Gecko/20100101 Firefox/76.0")
	req.Header.Set("X-CSRFToken", csrftoken)
	req.Header.Set("Referer", "https//www.instagram.com/")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept-Language", "ar,en-US;q=0.7,en;q=0.3")

	transport := http.Transport{}
	if proxy != "" {
		proxyUrl, _ := url.Parse(proxy)
		transport.Proxy = http.ProxyURL(proxyUrl) // set proxy proxyType://proxyIp:proxyPort
	}

	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //set ssl
	client := &http.Client{}
	if timeout > 0 {
		client = &http.Client{Timeout: time.Millisecond * time.Duration(timeout)}
	}
	var err error = nil
	client.Transport = &transport
	resp, err := client.Do(req)

	var reader io.ReadCloser
	var response = ""

	if resp != nil && resp.Body != nil {
		switch resp.Header.Get("Content-Encoding") {
		case "gzip":
			reader, _ = gzip.NewReader(resp.Body)
			defer reader.Close()
		default:
			reader = resp.Body
		}
		body, _ := ioutil.ReadAll(reader)
		response = string(body)
	}

	if err != nil || response == "" || resp == nil {
		if response != "" {
			return 3, response, resp.StatusCode, err
		}
		if err != nil {
			if strings.Contains(err.Error(), "no such host") {
				return 2, response, resp.StatusCode, err
			} else {
				return 4, response, resp.StatusCode, err
			}
		}
		return 5, response, resp.StatusCode, err
	}
	defer resp.Body.Close()

	if !strings.Contains(response, "\"username\":") && !strings.Contains(response, "This username isn't available") && !strings.Contains(response, "username_is_taken") && !strings.Contains(response, "username_held_by_others") {
		return 0, response, resp.StatusCode, err
	} else if strings.Contains(response, "username_held_by_others") {
		return 6, response, resp.StatusCode, err
	}
	return 1, response, resp.StatusCode, err
}

func CheckWebInstagram(us string, sessionid string, proxy string /*example: ( IpProxy:IpPort )*/, timeout int) (int, string, int) {

	var req *http.Request
	req, _ = http.NewRequest("GET", "https://www.instagram.com/"+us+"/?__a=1", nil)
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36")

	transport := http.Transport{}
	if proxy != "" {
		proxyUrl, _ := url.Parse(proxy)
		transport.Proxy = http.ProxyURL(proxyUrl) // set proxy proxyType://proxyIp:proxyPort
	}

	jar, _ := cookiejar.New(nil)
	if sessionid != "" {
		var cookies []*http.Cookie
		var cookie = &http.Cookie{}
		cookie = &http.Cookie{
			Name:   "sessionid",
			Value:  sessionid,
			Path:   "/",
			Domain: "instagram.com",
		}
		cookies = append(cookies, cookie)
		u, _ := url.Parse("https://i.instagram.com/api/v1/accounts/login/")
		jar.SetCookies(u, cookies)
	}

	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //set ssl
	client := &http.Client{}
	if sessionid != "" {
		if timeout > 0 {
			client = &http.Client{Jar: jar, Timeout: time.Millisecond * time.Duration(timeout)}
		} else {
			client = &http.Client{Jar: jar}
		}
	} else {
		if timeout > 0 {
			client = &http.Client{Timeout: time.Millisecond * time.Duration(timeout)}
		}
	}
	client.Transport = &transport
	resp, err := client.Do(req)

	var reader io.ReadCloser
	var response = ""

	if resp != nil {
		switch resp.Header.Get("Content-Encoding") {
		case "gzip":
			reader, _ = gzip.NewReader(resp.Body)
			defer reader.Close()
		default:
			reader = resp.Body
		}
		body, _ := ioutil.ReadAll(reader)
		response = string(body)
	}

	if err != nil || response == "" || resp == nil {
		if response != "" {
			return 3, response, resp.StatusCode
		}
		if err != nil {
			if strings.Contains(err.Error(), "no such host") {
				return 2, response, resp.StatusCode
			} else {
				return 4, response, resp.StatusCode
			}
		}
		return 5, response, resp.StatusCode
	}
	defer resp.Body.Close()

	if (!strings.Contains(response, "logging_page_id") && strings.Contains(response, "Page Not Found")) || (!strings.Contains(response, "logging_page_id") && strings.Contains(response, "{") && response == "{}") {
		return 0, response, resp.StatusCode
	}
	return 1, response, resp.StatusCode
}

func CheckInfoUsername(us string, cookies []*http.Cookie, csrftoken string, timeout int, api API) HttpResponse {

	url := "https://i.instagram.com/api/v1/feed/user/" + us + "/username/"

	headers := make(map[string]string)

	headers["X-CSRFToken"] = csrftoken

	return IR(url, nil, "", headers, api, "", cookies, true, timeout)

}

func CreateAccount(us string, email string, password string, guid string, csrftoken string, timeout int, api API, proxy string) (int, string) {

	_url := "accounts/create/"

	postData := make(map[string]string)
	_guid := ""
	if guid == "" {
		u, _ := uuid.NewUUID()
		_guid = u.String()
	} else {
		_guid = guid
	}

	postData["phone_id"] = _guid
	if csrftoken == "" {
		postData["_csrftoken"] = "missing"
	} else {
		postData["_csrftoken"] = csrftoken
	}
	postData["username"] = us
	postData["password"] = "(#"
	postData["email"] = "bumranhospital6d9@gmail.com"
	postData["device_id"] = _guid
	postData["guid"] = _guid
	res := IR(_url, postData, "", nil, api, "", nil, false, timeout)
	if res.Err == nil || res.Body == "" {
		if !strings.Contains(res.Body, "username") &&
			res.Body != "" && !strings.Contains(res.Body, "requests") &&
			!strings.Contains(res.Body, "request") &&
			!strings.Contains(res.Body, "please wait") &&
			!strings.Contains(res.Body, "wait") &&
			!strings.Contains(res.Body, "username_held_by_others") {
			return 0, res.Body
		} else if strings.Contains(res.Body, "username_held_by_others") {
			return 1, res.Body
		}
	}
	return 2, res.Body
}

func CheckUsername(us string, cookies []*http.Cookie, csrftoken string, pk string, InstaAPI API, timeout int, proxy string) HttpResponse {
	url := "https://i.instagram.com/api/v1/users/check_username/"

	var Cookies []*http.Cookie

	u, _ := uuid.NewUUID()
	guid := u.String()

	post := make(map[string]string)
	post["_uuid"] = guid
	post["_csrftoken"] = csrftoken
	post["username"] = us
	post["_uid"] = pk

	return IR(url, post, "", nil, InstaAPI, proxy, Cookies, true, timeout)
}

func CheckUserName(us string, guid string, csrftoken string, timeout int, api API) (int, string, HttpResponse) {

	_url := "accounts/create/"

	postData := make(map[string]string)
	_guid := ""
	if guid == "" {
		u, _ := uuid.NewUUID()
		_guid = u.String()
	} else {
		_guid = guid
	}

	postData["phone_id"] = _guid
	if csrftoken == "" {
		postData["_csrftoken"] = "missing"
	} else {
		postData["_csrftoken"] = csrftoken
	}
	postData["username"] = us
	postData["password"] = "(#"
	postData["email"] = "bumranhospital6d9@gmail.com"
	postData["device_id"] = _guid
	postData["guid"] = _guid
	res := IR(_url, postData, "", nil, api, "", nil, false, timeout)
	if res.Err == nil || res.Body == "" {
		if !strings.Contains(res.Body, "username") &&
			res.Body != "" && !strings.Contains(res.Body, "requests") &&
			!strings.Contains(res.Body, "request") &&
			!strings.Contains(res.Body, "please wait") &&
			!strings.Contains(res.Body, "wait") &&
			!strings.Contains(res.Body, "username_held_by_others") {
			return 0, res.Body, res
		} else if strings.Contains(res.Body, "username_held_by_others") {
			return 1, res.Body, res
		}
	}
	return 2, res.Body, res
}

func LoginWebInstagram(us string, ps string, proxy string, MiliTimeout int) HttpResponse {

	_url := "https://www.instagram.com/accounts/login/ajax/"
	data := "username=" + us + "&password=" + ps + "&queryParams={}&optIntoOneTap=false"

	var req *http.Request
	req, _ = http.NewRequest("POST", _url, bytes.NewBuffer([]byte(data)))

	req.Header.Set("Host", "www.instagram.com")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:75.0) Gecko/20100101 Firefox/75.0")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("X-CSRFToken", "zXW4lt83StVRrecNi0A6okN7MCNS2rvj")
	req.Header.Set("X-Instagram-AJAX", "fc6921a46e54")
	req.Header.Set("X-IG-App-ID", "936619743392459")
	req.Header.Set("X-IG-WWW-Claim", "0")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Origin", "https://www.instagram.com")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Referer", "https://www.instagram.com/")

	transport := http.Transport{}
	if proxy != "" {
		ProxyURL := &url.URL{Host: proxy}
		transport.Proxy = http.ProxyURL(ProxyURL)
	}
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{}
	if MiliTimeout != 0 {
		client = &http.Client{Timeout: time.Millisecond * time.Duration(MiliTimeout)}
	}

	client.Transport = &transport
	resp, err := client.Do(req)

	RawReq, _ := httputil.DumpRequest(req, true)
	ReqSize := float64(len(RawReq))
	if data != "" {
		ReqSize += float64(len([]byte(data)))
		ReqSize += 4
	}

	RawRes, _ := httputil.DumpResponse(resp, true)
	ResSize := float64(len(RawRes))

	if err != nil {
		return MakeHttpResponse(resp, req, err, ReqSize, ResSize)
	}
	defer resp.Body.Close()
	return MakeHttpResponse(resp, req, nil, ReqSize, ResSize)
}

func IR(iurl string, signedbody map[string]string, payload string,
	Headers map[string]string, api API, proxy string,
	cookie []*http.Cookie, usecookies bool, MiliTimeout int) HttpResponse {

	_url := iurl

	if ((!strings.Contains(_url, "https")) || (!strings.Contains(_url, "http"))) && _url[0] != '/' {
		_url = "https://i.instagram.com/api/v1/" + _url
	} else if ((!strings.Contains(_url, "https")) || (!strings.Contains(_url, "http"))) && _url[0] == '/' {
		_url = "https://i.instagram.com/api/v1" + _url
	}

	_api := API{}
	if api == (API{}) {
		_api = GetAPI()
	} else {
		_api = api
	}

	_payload := ""
	if signedbody != nil {
		_data, _ := json.Marshal(signedbody)
		_json := string(_data)
		_signed := fmt.Sprintf("%v.%s", HMACSHA256(_api.KEY, _json), _json)
		_payload = "ig_sig_key_version=" + _api.KeyVersion + "&signed_body=" + _signed
	} else if payload != "" {
		_payload = payload
	}

	var req *http.Request
	if _payload != "" {
		req, _ = http.NewRequest("POST", _url, bytes.NewBuffer([]byte(_payload)))
	} else {
		req, _ = http.NewRequest("GET", _url, nil)
	}

	req.Header.Set("User-Agent", "Instagram "+_api.VERSION+" Android (19/4.4.2; 480dpi; 1080x1920; samsung; SM-N900T; hltetmo; qcom; en_US)")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Cookie2", "$Version=1")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("X-IG-Connection-Type", "WIFI")
	req.Header.Set("X-IG-Capabilities", _api.CAPABILITIES)
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("X-FB-HTTP-Engine", "Liger")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "Keep-Alive")

	if Headers != nil {
		var keys []string
		for key := range Headers {
			keys = append(keys, key)
		}
		var values []string
		for _, value := range Headers {
			values = append(values, value)
		}

		for i := 0; i < len(keys); i++ {
			req.Header.Set(keys[i], values[i])
		}
	}

	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse(_url)
	jar.SetCookies(u, cookie)

	transport := http.Transport{}
	if proxy != "" {
		proxyUrl := &url.URL{Host: proxy}
		transport.Proxy = http.ProxyURL(proxyUrl)
	}
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{}
	if MiliTimeout != 0 {
		client = &http.Client{Timeout: time.Millisecond * time.Duration(MiliTimeout)}
	}
	if usecookies {
		if MiliTimeout != 0 {
			client = &http.Client{Timeout: time.Millisecond * time.Duration(MiliTimeout), Jar: jar}
		} else {
			client = &http.Client{Jar: jar}
		}
	}

	client.Transport = &transport
	resp, err := client.Do(req)

	RawReq, _ := httputil.DumpRequest(req, true)
	ReqSize := float64(len(RawReq))
	if _payload != "" {
		ReqSize += float64(len([]byte(_payload)))
		ReqSize += 4
	}

	if resp == nil {
		if err != nil {
			return MakeHttpResponse(nil, req, err, ReqSize, 0)
		}
		return MakeHttpResponse(nil, req, nil, ReqSize, 0)
	}
	RawRes, _ := httputil.DumpResponse(resp, true)
	ResSize := float64(len(RawRes))

	if err != nil {
		return MakeHttpResponse(resp, req, err, ReqSize, ResSize)
	}
	defer resp.Body.Close()
	return MakeHttpResponse(resp, req, nil, ReqSize, ResSize)
}

func MakeList(chars []string, l int) []string {
	var list []string
	var clearList []string
	var n = len(chars)
	ml(chars, "", n, l, &list)
	for _, v := range list {
		if v[:1] == "." || v[(len(v)-1):] == "." {
		} else {
			clearList = append(clearList, v)
		}
	}
	return clearList
}

func ml(chars []string, prefix string, n int, l int, list *[]string) {
	var copied []string
	if l == 0 {
		copied = *list
		copied = append(copied, prefix)
		*list = copied
		return
	}
	for i := 0; i < n; i++ {
		newPrefix := prefix + chars[i]
		ml(chars, newPrefix, n, l-1, list)
	}
}

func CreateUsernames(chars []string, length int) []string {
	t := []string{"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "_", "."}
	l := 3
	if length != 0 {
		l = length
	}
	if chars != nil {
		t = chars
	}
	return MakeList(t, l)
}

func StringWithCharset(length int, charset string) string {
	var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	var letters = []rune(charset)
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[seededRand.Intn(len(letters))]
	}
	return string(b)
}

func unique(intSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range intSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// GetProxies function
func GetProxies() ([]string, []string, []string) {

	var req *http.Request
	req, _ = http.NewRequest("GET", "https://raw.githubusercontent.com/fate0/proxylist/master/proxy.list", nil)
	req.Header.Set("Host", "raw.githubusercontent.com")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Accept-Language", "ar,en-US;q=0.7,en;q=0.3")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:67.0) Gecko/20100101 Firefox/67.0")
	req.Header.Set("Connection", "keep-alive")

	transport := http.Transport{}
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //set ssl
	client := &http.Client{}
	client.Transport = &transport
	resp, err := client.Do(req)
	_ = err

	var reader io.ReadCloser
	var response = ""

	if resp != nil {
		switch resp.Header.Get("Content-Encoding") {
		case "gzip":
			reader, _ = gzip.NewReader(resp.Body)
			defer reader.Close()
		default:
			reader = resp.Body
		}
		body, _ := ioutil.ReadAll(reader)
		response = string(body)
	}

	_Proxies := strings.Split(response, "}\n{")
	var HTTPSProxies []string
	var HTTPProxies []string

	for i := 0; i < len(_Proxies); i++ {
		if i == 0 {

			current := _Proxies[i] + "}"
			_proxy := make(map[string]interface{})
			json.Unmarshal([]byte(current), &_proxy)

			_type := fmt.Sprintf("%v", _proxy["type"])
			_ip := fmt.Sprintf("%v", _proxy["host"])
			_port := fmt.Sprintf("%v", _proxy["port"])

			if _type == "https" {
				HTTPSProxies = append(HTTPSProxies, _type+"://"+_ip+":"+_port)
			}
			if _type == "http" {
				HTTPProxies = append(HTTPProxies, _type+"://"+_ip+":"+_port)
			}

			continue
		}
		if i == len(_Proxies)-1 {

			current := "{" + _Proxies[i]
			_proxy := make(map[string]interface{})
			json.Unmarshal([]byte(current), &_proxy)

			_type := fmt.Sprintf("%v", _proxy["type"])
			_ip := fmt.Sprintf("%v", _proxy["host"])
			_port := fmt.Sprintf("%v", _proxy["port"])

			if _type == "https" {
				HTTPSProxies = append(HTTPSProxies, _type+"://"+_ip+":"+_port)
			}
			if _type == "http" {
				HTTPProxies = append(HTTPProxies, _type+"://"+_ip+":"+_port)
			}

			break
		}

		current := "{" + _Proxies[i] + "}"
		_proxy := make(map[string]interface{})
		json.Unmarshal([]byte(current), &_proxy)

		_type := fmt.Sprintf("%v", _proxy["type"])
		_ip := fmt.Sprintf("%v", _proxy["host"])
		_port := fmt.Sprintf("%v", _proxy["port"])

		if _type == "https" {
			HTTPSProxies = append(HTTPSProxies, _type+"://"+_ip+":"+_port)
		}
		if _type == "http" {
			HTTPProxies = append(HTTPProxies, _type+"://"+_ip+":"+_port)
		}

	}
	return HTTPSProxies, HTTPProxies, append(HTTPProxies, HTTPSProxies...)
}

func ssliceContains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func login(us string, ps string, proxy string, FakeCookies bool, InstaAPI API, timeout int) HttpResponse {
	url := "https://i.instagram.com/api/v1/accounts/login/"

	var Cookies []*http.Cookie

	u, _ := uuid.NewUUID()
	guid := u.String()

	post := make(map[string]string)
	post["phone_id"] = guid
	post["_csrftoken"] = "missing"
	post["username"] = us
	post["password"] = ps
	post["device_id"] = guid
	post["guid"] = guid
	post["login_attempt_count"] = "0"

	if FakeCookies {
		Cookies = APICreateCookies(-1, false, "", "")
		return IR(url, post, "", nil, InstaAPI, proxy, Cookies, true, timeout)
	}
	return IR(url, post, "", nil, InstaAPI, proxy, Cookies, true, timeout)
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// writeLines writes the lines to the given file.
func writeLines(lines []string, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, line := range lines {
		_, _ = fmt.Fprintln(w, line)
	}
	return w.Flush()
}

func RandRange(min int, max int) int {
	var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	_max := max + 1
	return seededRand.Intn(_max-min) + min
}

func replaceAtIndex(in string, r rune, i int) string {
	out := []rune(in)
	out[i] = r
	return string(out)
}

func b(bin int) bool {
	if bin == 0 {
		return false
	}
	if bin == 1 {
		return true
	}
	return false
}

func RandomChoice() bool {
	var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	min := 0
	max := 2
	return b(seededRand.Intn(max-min) + min)
}

func GenerateRandomString(length int, numbers bool, uppers bool, lowers bool, symbols bool, NotStartWithNumber bool) string {
	var _uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	var _lowers = "abcdefghijklmnopqrstuvwxyz"
	var _numbers = "0123456789"
	var _symbols = "!@#$%^&*()_-+=\\/,.?<>|"
	var charset = ""
	if numbers {
		charset += charset + _numbers
	}
	if lowers {
		charset += charset + _lowers
	}
	if uppers {
		charset += charset + _uppers
	}
	if symbols {
		charset += charset + _symbols
	}
	if charset == "" {
		log.Println("Are an idoit ?")
		charset = "Yes, Im an Idoit"
	}
	rnd := StringWithCharset(length, charset)
	if NotStartWithNumber {
		matched, _ := regexp.MatchString("[0-9]", string(rnd[0]))
		if matched {
			chars := string(_lowers)
			if RandomChoice() {
				chars = string(_uppers)
			}
			rnd = replaceAtIndex(rnd, rune(chars[RandRange(0, len(chars)-1)]), 0)
		}
	}
	return rnd
}

// APICreateCookies function
func APICreateCookies(URLType int, Legit bool, dsUserId string, dsUser string) []*http.Cookie {

	var mid string
	var csrftoken string
	var sessionid string
	var ds_user_id string = dsUserId
	var ds_user string = dsUser
	var rur string

	if Legit {
		CLegit := GetLegitCookies()
		_url, _ := url.Parse("https://www.instagram.com/")
		var Cookies = CLegit.Cookies(_url)
		for i := 0; i < len(Cookies); i++ {
			if strings.Contains(strings.ToLower(Cookies[i].Name), "csrftoken") {
				csrftoken = Cookies[i].Value
			}
			if strings.Contains(strings.ToLower(Cookies[i].Name), "mid") {
				mid = Cookies[i].Value
			}
		}
	} else {
		mid = "XSy" + GenerateRandomString(25, true, true, true, false, false) // was without XSx and was 27 and true start with char
		csrftoken = GenerateRandomString(32, true, true, true, false, true)
		NewChar := '_'
		if RandomChoice() {
			NewChar = '-'
		}
		if RandomChoice() {
			mid = replaceAtIndex(mid, NewChar, (RandRange(4, 27))) // was 1, 28
		}
	}

	Random_rur := RandRange(0, 4)

	if Random_rur == 0 {
		rur = "PRN"
	}
	if Random_rur == 1 {
		rur = "ASH"
	}
	if Random_rur == 2 {
		rur = "ATN"
	}
	if Random_rur == 3 {
		rur = "FRC"
	}
	if Random_rur == 4 {
		rur = "FTW"
	}

	if ds_user_id == "" {
		ds_user_id = GenerateRandomString(10, true, false, false, false, false)
	}

	sessionid = ds_user_id + "%3A" + GenerateRandomString(14, true, true, true, false, false) + "%3A" + GenerateRandomString(2, true, false, false, false, false)

	var cookies []*http.Cookie

	cookie0 := &http.Cookie{
		Name:     "sessionid",
		Value:    sessionid,
		Path:     "/",
		Domain:   "instagram.com",
		Secure:   true,
		HttpOnly: true,
	}
	cookies = append(cookies, cookie0)

	cookie1 := &http.Cookie{
		Name:   "mid",
		Value:  mid,
		Path:   "/",
		Domain: "instagram.com",
		Secure: true,
	}
	cookies = append(cookies, cookie1)

	cookie2 := &http.Cookie{
		Name:   "csrftoken",
		Value:  csrftoken,
		Path:   "/",
		Domain: "instagram.com",
		Secure: true,
	}
	cookies = append(cookies, cookie2)

	cookie4 := &http.Cookie{
		Name:   "ds_user_id",
		Value:  ds_user_id,
		Path:   "/",
		Domain: "instagram.com",
		Secure: true,
	}
	cookies = append(cookies, cookie4)

	cookie3 := &http.Cookie{
		Name:     "rur",
		Value:    rur,
		Path:     "/",
		Domain:   "instagram.com",
		Secure:   true,
		HttpOnly: true,
	}
	cookies = append(cookies, cookie3)

	cookie5 := &http.Cookie{
		Name:     "shbts",
		Value:    "1" + GenerateRandomString(9, true, false, false, false, false) + "." + GenerateRandomString(7, true, false, false, false, false),
		Path:     "/",
		Domain:   "instagram.com",
		Secure:   true,
		HttpOnly: true,
	}
	cookies = append(cookies, cookie5)

	if ds_user == "" {
		ds_user = GenerateRandomString(RandRange(3, 10), true, false, true, false, true)
	}

	cookie6 := &http.Cookie{
		Name:     "ds_user",
		Value:    ds_user,
		Path:     "/",
		Domain:   "instagram.com",
		Secure:   true,
		HttpOnly: true,
	}
	cookies = append(cookies, cookie6)

	cookie7 := &http.Cookie{
		Name:     "shbid",
		Value:    "11" + GenerateRandomString(3, true, false, false, false, false),
		Path:     "/",
		Domain:   "instagram.com",
		Secure:   true,
		HttpOnly: true,
	}
	cookies = append(cookies, cookie7)

	// u, _ := url.Parse("https://www.instagram.com/")

	// jar, _ := cookiejar.New(nil)
	// jar.SetCookies(u, cookies)

	return cookies
}

// CreateCookies function
func CreateCookies(URLType int, Legit bool, dsUserId string) http.CookieJar {

	var mid string
	var csrftoken string
	var urlgen string
	var sessionid string
	var ds_user_id string = dsUserId
	var rur string

	if Legit {
		CLegit := GetLegitCookies()
		_url, _ := url.Parse("https://www.instagram.com/")
		var Cookies = CLegit.Cookies(_url)
		for i := 0; i < len(Cookies); i++ {
			if strings.Contains(strings.ToLower(Cookies[i].Name), "csrftoken") {
				csrftoken = Cookies[i].Value
			}
			if strings.Contains(strings.ToLower(Cookies[i].Name), "mid") {
				mid = Cookies[i].Value
			}
		}
	} else {
		mid = "XShb" + GenerateRandomString(24, b(1), b(1), true, false, true) // was without XShy and was 27
		csrftoken = GenerateRandomString(32, b(1), b(1), true, false, true)
		NewChar := '_'
		if RandomChoice() {
			NewChar = '-'
		}
		if RandomChoice() {
			mid = replaceAtIndex(mid, NewChar, (RandRange(4, 27))) // was 1, 28
		}
	}

	Random_rur := RandRange(0, 4)

	if Random_rur == 0 {
		rur = "PRN"
	}
	if Random_rur == 1 {
		rur = "ASH"
	}
	if Random_rur == 2 {
		rur = "ATN"
	}
	if Random_rur == 3 {
		rur = "FRC"
	}
	if Random_rur == 4 {
		rur = "FTW"
	}

	if ds_user_id == "" {
		ds_user_id = GenerateRandomString(10, true, false, false, false, false)
	}

	sessionid = ds_user_id + "%3A" + GenerateRandomString(14, true, true, true, false, false) + "%3A" + GenerateRandomString(2, true, false, false, false, false)

	begin, _ := url.QueryUnescape("%22%7B%5C%22")
	end, _ := url.QueryUnescape("%5C%22%3A%20")
	final := end + "25019}:1hl"                                        // was 1h
	ffinal := "}:1hl"                                                  // was 1h
	lastone := GenerateRandomString(3, true, true, true, false, false) // was 4
	eend, _ := url.QueryUnescape("25019%5C054%20%5C%22")
	theend := GenerateRandomString(27, true, true, true, false, false)
	comma, _ := url.QueryUnescape("%22")
	cr := '_'

	if RandomChoice() {
		cr = '-'
	}
	if RandomChoice() {
		theend = replaceAtIndex(theend, cr, (RandRange(1, 26)))
	}

	Random_urlgen := RandRange(0, 4)
	if URLType != -1 {
		Random_urlgen = URLType
	}

	if Random_urlgen == 0 {
		urlgen = fmt.Sprintf("%s%s%s%s%s%s%s:%s%s", begin, randomdata.IpV4Address(), end, eend, randomdata.IpV6Address(), final, lastone, theend, comma)
	}
	if Random_urlgen == 1 {
		urlgen = fmt.Sprintf("%s%s%s25019%s%s:%s%s", begin, randomdata.IpV4Address(), end, ffinal, lastone, theend, comma)
	}
	if Random_urlgen == 2 {
		urlgen = fmt.Sprintf("%s%s%s25019%s%s:%s%s", begin, randomdata.IpV6Address(), end, ffinal, lastone, theend, comma)
	}
	if Random_urlgen == 3 {
		urlgen = fmt.Sprintf("%s%s%s%s%s%s%s:%s%s", begin, randomdata.IpV6Address(), end, eend, randomdata.IpV6Address(), final, lastone, theend, comma)
	}
	if Random_urlgen == 4 {
		urlgen = fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s:%s%s", begin, randomdata.IpV6Address(), end, eend, randomdata.IpV6Address(), end, eend, randomdata.IpV6Address(), final, lastone, theend, comma)
	}

	var jar http.CookieJar
	var cookies []*http.Cookie

	cookie0 := &http.Cookie{
		Name:     "sessionid",
		Value:    sessionid,
		Path:     "/",
		Domain:   ".instagram.com",
		Secure:   true,
		HttpOnly: true,
	}
	cookies = append(cookies, cookie0)

	cookie1 := &http.Cookie{
		Name:   "mid",
		Value:  mid,
		Path:   "/",
		Domain: ".instagram.com",
		Secure: true,
	}
	cookies = append(cookies, cookie1)

	cookie2 := &http.Cookie{
		Name:   "csrftoken",
		Value:  csrftoken,
		Path:   "/",
		Domain: ".instagram.com",
		Secure: true,
	}
	cookies = append(cookies, cookie2)

	cookie4 := &http.Cookie{
		Name:   "ds_user_id",
		Value:  ds_user_id,
		Path:   "/",
		Domain: ".instagram.com",
		Secure: true,
	}
	cookies = append(cookies, cookie4)

	cookie3 := &http.Cookie{
		Name:     "rur",
		Value:    rur,
		Path:     "/",
		Domain:   ".instagram.com",
		Secure:   true,
		HttpOnly: true,
	}
	cookies = append(cookies, cookie3)

	cookie5 := &http.Cookie{
		Name:     "urlgen",
		Value:    urlgen,
		Path:     "/",
		Domain:   ".instagram.com",
		Secure:   true,
		HttpOnly: true,
	}
	cookies = append(cookies, cookie5)

	u, _ := url.Parse("https://www.instagram.com/")

	jar.SetCookies(u, cookies)

	return jar
}

// GetLegitCookies function
func GetLegitCookies() http.CookieJar {
	jar := CreateCookies(-1, false, "")
	//jar, _ := cookiejar.New(nil)
	var req *http.Request
	req, _ = http.NewRequest("GET", "https://www.instagram.com/", nil)
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36")
	transport := http.Transport{}
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //set ssl
	client := &http.Client{Jar: jar}
	client.Transport = &transport
	client.Do(req)
	return jar
}

func GetProfile(Cookies []*http.Cookie, api API, timeout int) (map[string]string, HttpResponse) {
	res := IR("accounts/current_user/?edit=true", nil, "", nil, api, "", Cookies, true, timeout)
	var profile = make(map[string]string)

	var username = ""
	_username := regexp.MustCompile("\"username\": \"(.*?)\",").FindStringSubmatch(res.Body)
	if _username != nil {
		username = _username[1]
	}
	var biography = ""
	_biography := regexp.MustCompile("\"biography\": \"(.*?)\",").FindStringSubmatch(res.Body)
	if _biography != nil {
		biography = _biography[1]
	}

	var fullName = ""
	_fullName := regexp.MustCompile("\"full_name\": \"(.*?)\",").FindStringSubmatch(res.Body)
	if _fullName != nil {
		fullName = _fullName[1]
	}

	var phoneNumber = ""
	_phoneNumber := regexp.MustCompile("\"phone_number\": \"(.*?)\",").FindStringSubmatch(res.Body)
	if _phoneNumber != nil {
		phoneNumber = _phoneNumber[1]
	}

	var email = ""
	_email := regexp.MustCompile("\"email\": \"(.*?)\"").FindStringSubmatch(res.Body)
	if _email != nil {
		email = _email[1]
	}
	var gender = ""
	_gender := regexp.MustCompile("\"gender\": \"(.*?)\",").FindStringSubmatch(res.Body)
	if _gender != nil {
		gender = _gender[1]
	}

	var externalUrl = ""
	_externalUrl := regexp.MustCompile("\"external_url\": \"(.*?)\",").FindStringSubmatch(res.Body)
	if _externalUrl != nil {
		externalUrl = _externalUrl[1]
	}

	var isVerified = ""
	_isVerified := regexp.MustCompile("\"is_verified\": \"(.*?)\",").FindStringSubmatch(res.Body)
	if _isVerified != nil {
		isVerified = _isVerified[1]
	}

	profile["username"] = username
	profile["biography"] = biography
	profile["full_name"] = fullName
	profile["phone_number"] = phoneNumber
	profile["email"] = email
	profile["gender"] = gender
	profile["external_url"] = externalUrl
	profile["is_verified"] = isVerified

	return profile, res
}

func Edit(_guid string, Cookies []*http.Cookie, username string, email string, biography string, external_url string, full_name string, phone_number string, gender string, pk string, csrftoken string, api API, timeout int, _profile map[string]string) (HttpResponse, map[string]string) {

	var guid string
	if _guid != "" {
		guid = _guid
	} else {
		u, _ := uuid.NewUUID()
		guid = u.String()
	}

	var profile map[string]string
	if _profile == nil {
		profile, _ = GetProfile(Cookies, api, timeout)
	} else {
		profile = _profile
	}

	var _external_url string
	var _biography string
	var _username string
	var _email string
	var _full_name string
	var _phone_number string
	var _gender string
	var _csrftoken string
	var _pk string

	if username == "" {
		_username = profile["username"]
	} else {
		_username = username
	}
	if external_url == "" {
		_external_url = profile["external_url"]
	} else {
		_external_url = external_url
	}
	if biography == "" {
		_biography = profile["biography"]
	} else {
		_biography = biography
	}
	if email == "" {
		_email = profile["email"]
	} else {
		_email = email
	}
	if full_name == "" {
		_full_name = profile["full_name"]
	} else {
		_full_name = full_name
	}
	if phone_number == "" {
		_phone_number = profile["phone_number"]
	} else {
		_phone_number = phone_number
	}
	if gender == "" {
		_gender = profile["gender"]
	} else {
		_gender = gender
	}
	if csrftoken == "" {
		_csrftoken = "missing"
	} else {
		_csrftoken = csrftoken
	}
	if pk == "" {
		_pk = "missing"
	} else {
		_pk = pk
	}

	postData := make(map[string]string)
	postData["external_url"] = _external_url
	postData["_uid"] = _pk
	postData["_uuid"] = guid
	postData["biography"] = _biography
	postData["_csrftoken"] = _csrftoken
	postData["username"] = _username
	postData["email"] = strings.ReplaceAll(strings.ReplaceAll(_email, "+", "%2B"), "@", "%40")
	postData["full_name"] = _full_name
	postData["phone_number"] = _phone_number
	postData["gender"] = _gender //1 = male, 2 = female

	return IR("accounts/edit_profile/", postData, "", nil, api, "", Cookies, true, timeout), postData
}
