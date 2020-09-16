package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"
)

var start = false
var editingStarted = false
var unleash = false
var startedThreads = 0
var target string
var hunted = false
var targetChanged = false
var twoMod = false
var attempts = 0
var receiverUS string
var sLPTime = 0
var f *os.File
var ferror error
var logger *log.Logger
var _log = false
var timeOut = 0
var guid string
var receiverProfile map[string]string
var changeTo string
var super = false
var lastThread = 0
var wakeup chan int
var safe = false
var max = 0
var started = false
var rate = 0
var outputs []int
var swap = true
var day = false
var banned = false
var checkMD = 0
var register = false
var wellness = false
var checkMDDay = 0

var accountWEB []string
var accountAPP []string
var infoAPP []string
var LoginAPP []string
var checkUsernameAPP []string

var accountWEBBlockingRate float64
var accountAPPBlockingRate float64
var infoAPPBlockingRate float64
var LoginAPPBlockingRate float64
var checkUsernameAPPBlockingRate float64

//ThreadsPerMoment is the number of threads
var ThreadsPerMoment int

//TargetCookies is the target account's cookies
var TargetCookies []*http.Cookie

//TargetCookiesMap is the target account's cookies map
var TargetCookiesMap = make(map[string]string)

//TargetEM is the new email for the target
var TargetEM string

//receiverCookies is the receiver account's cookies
var receiverCookies []*http.Cookie

//receiverCookiesMap is the receiver account's cookies map
var receiverCookiesMap = make(map[string]string)

//receiverEM is the new email for the receiver
var receiverEM string

//InstaAPI is the API struct
var InstaAPI = GetAPI()

//DeleteLine Deletes A single line
func DeleteLine() { print("\033[F"); print("\033[K") }

//ClearConsole Deletes All lines
func ClearConsole() { print("\033[H\033[2J") }

func stringAllSliceContains(s []string, e string) bool {
	for _, a := range s {
		if !strings.Contains(a, e) {
			return false
		}
	}
	return true
}

func stringSliceContains(s []string, e string) bool {
	for _, a := range s {
		if strings.Contains(a, e) {
			return true
		}
	}
	return false
}

func contains(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func allSame(s []int, e int) bool {
	for _, a := range s {
		if a != e {
			return false
		}
	}
	return true
}

func percentOf(s []string, e string) float64 {
	if s == nil {
		return 0
	}
	if len(s) == 0 {
		return 0
	}
	var count float64 = 0.0
	for _, a := range s {
		if strings.Contains(a, e) {
			count++
		}
	}
	return float64(count/float64(len(s))) * 100.0
}

func percentOfSame(s []string, e string) float64 {
	if s == nil {
		return 0
	}
	if len(s) == 0 {
		return 0
	}
	var count float64 = 0.0
	for _, a := range s {
		if a == e {
			count++
		}
	}
	return float64(count/float64(len(s))) * 100.0
}

//end is the end screen
func end(s int) {

	R := color.New(color.FgRed, color.Bold)
	G := color.New(color.FgGreen, color.Bold)

	ClearConsole()

	R.Println("    __  __                             ")
	R.Println("   / / / /__  _________ ___  ___  _____")
	R.Println("  / /_/ / _ \\/ ___/ __ `__ \\/ _ \\/ ___/")
	R.Println(" / __  /  __/ /  / / / / / /  __(__  ) ")
	R.Println("/_/ /_/\\___/_/  /_/ /_/ /_/\\___/____/  ")
	fmt.Println()

	if s == 0 {
		G.Println("Successfully hunt: " + target)
	} else if s == 1 {
		R.Println("Error !")
	} else {
		G.Println("Thank you for using \"Hermes\"")
	}

	fmt.Println()
	color.Blue("By Hades, inst: @ctpe")
	fmt.Println()

	os.Exit(0)

}

var accWEBFlags bool = false
var LoginAPPFlags bool = false

func progress() {

	ClearConsole()

	println("\u001b[38;5;31m    __  __                             \u001b[0m")
	println("\u001b[38;5;31m   / / / /__  _________ ___  ___  _____\u001b[0m")
	println("\u001b[38;5;31m  / /_/ / _ \\/ ___/ __ `__ \\/ _ \\/ ___/\u001b[0m")
	println("\u001b[38;5;31m / __  /  __/ /  / / / / / /  __(__  ) \u001b[0m")
	println("\u001b[38;5;31m/_/ /_/\\___/_/  /_/ /_/ /_/\\___/____/  \u001b[0m")
	println()

	for {

		runtime.Gosched()

		if hunted {
			end(0)
		}

		if rate == 0 {
			_ = wakeup
		}

		// 1- check by every func then switch to the next
		// 2- fuck all func alone then go to the next if it get blocked

		accountWEBBlockingRate1 := percentOfSame(accountWEB, "-")
		accountAPPBlockingRate1 := percentOfSame(accountAPP, "-")
		infoAPPBlockingRate1 := percentOfSame(infoAPP, "-")
		// LoginAPPBlockingRate1 := percentOfSame(LoginAPP, "-")
		checkUsernameAPPBlockingRate1 := percentOfSame(checkUsernameAPP, "-")

		accountWEBBlockingRate = percentOf(accountWEB, "Please wait a few")
		accountAPPBlockingRate = percentOf(accountAPP, "Please wait a few")
		infoAPPBlockingRate = percentOf(infoAPP, "Please wait a few")
		// LoginAPPBlockingRate2 := percentOf(LoginAPP, "ip_block")
		// LoginAPPBlockingRate := percentOf(LoginAPP, "Please wait a few")
		// LoginAPPBlockingRate3 := percentOf(LoginAPP, "sentry_block")
		checkUsernameAPPBlockingRate = percentOf(checkUsernameAPP, "Please wait a few")

		// if contains "ip_block" or "spam" use proxy + change API + change Account(Cookies)

		// f1 := accountWEBBlockingRate >= 5.0 || accountAPPBlockingRate >= 5.0 || infoAPPBlockingRate >= 5.0 ||
		// 	LoginAPPBlockingRate >= 5.0 || checkUsernameAPPBlockingRate >= 5.0 || LoginAPPBlockingRate2 >= 5.0

		f1 := accountWEBBlockingRate >= 5.0 || accountAPPBlockingRate >= 5.0 || infoAPPBlockingRate >= 5.0 ||
			checkUsernameAPPBlockingRate >= 5.0

		f2 := accountWEBBlockingRate1 > 30.0
		//f3 := LoginAPPBlockingRate1 > 30.0
		f4 := accountAPPBlockingRate1 > 30.0
		f5 := checkUsernameAPPBlockingRate1 > 30.0
		f6 := infoAPPBlockingRate1 > 30.0

		//f7 := LoginAPPBlockingRate2 > 2.0 || LoginAPPBlockingRate3 > 2.0

		//if f1 || f2 || f3 || f4 || f5 || f6 || f7 || accWEBFlags || LoginAPPFlags {
		if f1 || f2 || f4 || f5 || f6 || accWEBFlags { //|| LoginAPPFlags {

			if accWEBFlags || LoginAPPFlags {
				accWEBFlags = false
				//LoginAPPFlags = false
			}

			if day {
				if !register {
					if checkMDDay >= 2 {
						checkMDDay = 0
					} else {
						checkMDDay++
					}
				} else {
					// if checkMDDay >= 2 {
					// 	checkMDDay = 0
					// } else {
					// 	checkMDDay++
					// }

					// ??
				}
			} else {
				if !register {
					if checkMD >= 3 {
						checkMD = 0
					} else {
						checkMD++
					}
				} else {
					// if checkMD >= 3 {
					// 	checkMD = 0
					// } else {
					// 	checkMD++
					// }

					// ??
				}
			}

			accountWEB = make([]string, 0)
			accountAPP = make([]string, 0)
			infoAPP = make([]string, 0)
			//LoginAPP = make([]string, 0)
			checkUsernameAPP = make([]string, 0)

		}

		flag1 := attempts >= 1

		flag2 := false
		if swap {
			flag2 = rate >= 30
		} else {
			flag2 = rate >= 10
		}

		flag := flag1 && flag2 && wellness
		if flag {
			safe = true
		}

		runningGoroutines := runtime.NumGoroutine()
		max = runtime.GOMAXPROCS(-1)

		// if runningGoroutines > max && max < 1000 {
		// 	max++
		// 	runtime.GOMAXPROCS(max)
		// }

		output := [12]string{}
		output[0] = fmt.Sprintf("\u001b[38;5;50m%s\u001b[0m \u001b[38;5;242m%s\u001b[0m", "Progress", "[")
		output[1] = fmt.Sprintf("   \u001b[38;5;208m%s\u001b[0m: \u001b[38;5;35m%v\u001b[0m,", "Username", receiverUS)
		output[2] = fmt.Sprintf("   \u001b[38;5;208m%s\u001b[0m: \u001b[38;5;35m%v\u001b[0m,", "Target", target)
		output[3] = fmt.Sprintf("   \u001b[38;5;208m%s\u001b[0m: \u001b[38;5;35m%v\u001b[0m,", "Checking Method", checkMD)
		output[4] = fmt.Sprintf("   \u001b[38;5;208m%s\u001b[0m: \u001b[38;5;35m%v\u001b[0m,", "Started Gorountines", startedThreads)
		output[5] = fmt.Sprintf("   \u001b[38;5;208m%s\u001b[0m: \u001b[38;5;35m%v\u001b[0m,", "Attempts", attempts)
		output[6] = fmt.Sprintf("   \u001b[38;5;208m%s\u001b[0m: \u001b[38;5;35m%v\u001b[0m \u001b[38;5;242mAttempts\u001b[0m/\u001b[38;5;242mSecond\u001b[0m,", "Speed", rate)
		output[7] = fmt.Sprintf("   \u001b[38;5;208m%s\u001b[0m: \u001b[38;5;35m%v\u001b[0m,", "Last Gorountine", lastThread)
		output[8] = fmt.Sprintf("   \u001b[38;5;208m%s\u001b[0m: \u001b[38;5;35m%v\u001b[0m,", "Max Gorountines", max)
		output[9] = fmt.Sprintf("   \u001b[38;5;208m%s\u001b[0m: \u001b[38;5;35m%v\u001b[0m,", "Running Gorountines", runningGoroutines)
		if safe {
			output[10] = fmt.Sprintf("   \u001b[38;5;208m%s\u001b[0m: \u001b[38;5;35m%v\u001b[0m,", "Safe", "Yes")
		} else {
			output[10] = fmt.Sprintf("   \u001b[38;5;208m%s\u001b[0m: \u001b[38;5;35m%v\u001b[0m,", "Safe", "No")
		}
		output[11] = fmt.Sprintf("\u001b[38;5;242m%s\u001b[0m", "]")

		for i := 0; i < len(output); i++ {
			fmt.Println(output[i])
		}

		started = true

		time.Sleep(time.Millisecond * 250)

		for i := 0; i < len(output); i++ {
			DeleteLine()
		}

	}
}

func startThreads(th int) {
	for t := 0; t < th; t++ {
		go Check()
		time.Sleep(time.Millisecond)
	}
}

func calculate() {
	for {
		AttemptsCounts1 := int(attempts)
		time.Sleep(time.Second * 1)
		AttemptsCounts2 := int(attempts)
		rate = AttemptsCounts2 - AttemptsCounts1 // rate = Attempts Per One Second
	}
}

//Check is the swap funcrion
func Check() {
	startedThreads++
	var n = int(startedThreads)
	for {
		runtime.Gosched()
		if start {
			if unleash {
				var res HttpResponse
				var result string = ""
				var stu = 0
				var done = false
				if swap {
					res, _ = Edit(guid, receiverCookies, target, "", "By Hermes Tool @ctpe", "https://i.instagram.com/ctpe", "Hi", "", "", receiverCookiesMap["ds_user_id"], receiverCookiesMap["csrftoken"], InstaAPI, timeOut, receiverProfile)
				} else { //if !day && !banned {

					/*
						try other APIs avoiding the block or use all of them, every API used if the other is blocked on so on in a loop
						[1] https://www.instagram.com/username/?__a=1 (A lot of errors)
						[2] WEB create Account x
						[3] APP create Account x
						[4] APP "check/username/" API x
						[5] APP profile info x
						-------- Additionals --------
						[1] Changing Cookies, Add them, Delete them, Legit Cookies
						[2] Proxies(Private, Public)
						https://i.instagram.com/api/v1/si/fetch_headers/?challenge_type=signup&guid=6c1f2f72-7023-40de-ae1e-7f267c01bba4
					*/

					if !day { // ! 14 days mod

						// if checkMD == 0 { // change
						// 	resp := login(target, "dduih89yntg6t6b98bt6", "", false, InstaAPI, timeOut)
						// 	result = resp.Body
						// 	stu = resp.ResStatus
						// 	if strings.Contains(res.Body, "belong to an account") && !strings.Contains(res.Body, "ip_block") {
						// 		s := CheckUsername(target, receiverCookies, receiverCookiesMap["csrftoken"], receiverCookiesMap["ds_user_id"], InstaAPI, timeOut, "")
						// 		result = s.Body
						// 		stu = resp.ResStatus
						// 		if strings.Contains(s.Body, "available\": true") {
						// 			done = true
						// 		}
						// 	}
						// 	_ = stu
						// 	if checkMD == 0 {
						// 		if result == "" {
						// 			LoginAPP = append(LoginAPP, "-")
						// 		} else {
						// 			LoginAPP = append(LoginAPP, result)
						// 		}
						// 	}
						// }

						if checkMD == 0 {
							s := CheckInfoUsername(target, receiverCookies, receiverCookiesMap["csrftoken"], 0, InstaAPI)
							result = s.Body

							if checkMD == 0 {
								if result == "" {
									infoAPP = append(infoAPP, "-")
								} else {
									infoAPP = append(infoAPP, result)
								}
							}

							stu = s.ResStatus
							if strings.Contains(result, "\"items\": []") && strings.Contains(result, "\"num_results\": 0") && strings.Contains(result, "\"status\": \"ok\"") && !(strings.Contains(result, "more_available") || strings.Contains(result, "auto_load_more_enabled")) {
								done = true
							}
						}

						if checkMD == 1 {
							s := CheckUsername(target, receiverCookies, receiverCookiesMap["csrftoken"], receiverCookiesMap["ds_user_id"], InstaAPI, timeOut, "")
							result = s.Body
							if checkMD == 1 {
								if result == "" {
									checkUsernameAPP = append(checkUsernameAPP, "-")
								} else {
									checkUsernameAPP = append(checkUsernameAPP, result)
								}
							}
							stu = s.ResStatus
							if strings.Contains(result, "available\": true") {
								done = true
							}
						}

						if checkMD == 2 {
							flag, result, stu, _ := accountCreateWEBCheck(target, receiverCookiesMap["csrftoken"], "", timeOut)
							_ = stu
							if checkMD == 2 {
								if result == "" {
									accountWEB = append(accountWEB, "-")
								} else {
									accountWEB = append(accountWEB, result)
								}
							}
							if flag == 0 {
								done = true
							} else if flag == 2 {
								accWEBFlags = true
							} else if flag == 6 {
								day = true
							}
						}

						if checkMD == 3 {
							s, result, r := CheckUserName(target, guid, receiverCookiesMap["csrftoken"], timeOut, InstaAPI)
							if checkMD == 3 {
								if result == "" {
									accountAPP = append(accountAPP, "-")
								} else {
									accountAPP = append(accountAPP, result)
								}
							}
							stu = r.ResStatus
							if s == 0 {
								done = true
							} else if s == 1 {
								day = true
							}
						}

					} else { // 14 days mod

						if checkMDDay == 0 {
							s := CheckUsername(target, receiverCookies, receiverCookiesMap["csrftoken"], receiverCookiesMap["ds_user_id"], InstaAPI, timeOut, "")
							result = s.Body
							if checkMDDay == 0 {
								if result == "" {
									checkUsernameAPP = append(checkUsernameAPP, "-")
								} else {
									checkUsernameAPP = append(checkUsernameAPP, result)
								}
							}
							stu = s.ResStatus
							if strings.Contains(result, "available\": true") {
								done = true
							}
						}

						if checkMDDay == 1 {
							flag, result, stu, _ := accountCreateWEBCheck(target, receiverCookiesMap["csrftoken"], "", timeOut)
							_ = stu
							if checkMDDay == 1 {
								if result == "" {
									accountWEB = append(accountWEB, "-")
								} else {
									accountWEB = append(accountWEB, result)
								}
							}
							if flag == 0 {
								done = true
							} else if flag == 2 {
								accWEBFlags = true
							} else if flag == 6 {
								day = true
							}
						}

						if checkMDDay == 2 {
							s, result, r := CheckUserName(target, guid, receiverCookiesMap["csrftoken"], timeOut, InstaAPI)
							if checkMDDay == 2 {
								if result == "" {
									accountAPP = append(accountAPP, "-")
								} else {
									accountAPP = append(accountAPP, result)
								}
							}
							stu = r.ResStatus
							if s == 0 {
								done = true
							} else if s == 1 {
								day = true
							}
						}

					}

				}
				outputs = append(outputs, res.ResStatus)
				attempts++
				lastThread = n
				editingStarted = true
				if _log {
					if swap {
						logger.Println("--EditAttempt#" + strconv.Itoa(attempts) + "--")
						if res.Body != "" {
							logger.Println(res.Body)
						}
						logger.Println(res.ResStatus)
					} else {
						logger.Println("--CheckAttempt#" + strconv.Itoa(attempts) + "--")
						if result != "" && len(result) > 50 {
							logger.Println(result[:50])
						} else if result != "" {
							logger.Println(result)
						}
						logger.Println(stu)
					}
				}
				if swap {
					if strings.Contains(res.Body, "\"user\":") && strings.Contains(res.Body, "\"status\": \"ok\"") {
						hunted = true
						start = false
						unleash = false
						editingStarted = false
						break
					}
				} else {
					if done { //Used MOD
						errors := 0
						for {
							if errors == 10 {
								break
							}
							res, _ = Edit(guid, receiverCookies, target, "", "By Hermes Tool @ctpe", "https://i.instagram.com/ctpe", "Hi", "", "", receiverCookiesMap["ds_user_id"], receiverCookiesMap["csrftoken"], InstaAPI, 60000, receiverProfile)
							if strings.Contains(res.Body, "\"user\":") && strings.Contains(res.Body, "\"status\": \"ok\"") {
								hunted = true
								start = false
								unleash = false
								editingStarted = false
								break
							}
							errors++
						}
						if hunted == false {
							break
						} else {
							end(1)
						}
					}
				}
				if sLPTime != 0 {
					time.Sleep(time.Millisecond * time.Duration(sLPTime))
				}
			}
		}
	}
}

func changeUsername() {
	for {
		if unleash {
			if editingStarted && safe {
				res, _ := Edit(guid, TargetCookies, changeTo, "", "By Hermes Tool @ctpe", "https://i.instagram.com/ctpe", "Hi", "", "", TargetCookiesMap["ds_user_id"], TargetCookiesMap["csrftoken"], InstaAPI, 1000*60, nil)
				if strings.Contains(res.Body, "{\"user\":") && strings.Contains(res.Body, "\"username\":") {
					targetChanged = true
					break
				}
			}
		}
	}
}

// ATOS .
func ATOS(asciiNum []int) string {
	res := ""
	for i := 0; i < len(asciiNum); i++ {
		character := string(asciiNum[i])
		res += (character)
	}
	return res
}

func main() {

	u, _ := uuid.NewUUID()
	guid = u.String()

	var choice string

	G := color.New(color.FgGreen, color.Bold)
	R := color.New(color.FgRed, color.Bold)

	ClearConsole()

	println("\u001b[38;5;31m    __  __                             \u001b[0m")
	println("\u001b[38;5;31m   / / / /__  _________ ___  ___  _____\u001b[0m")
	println("\u001b[38;5;31m  / /_/ / _ \\/ ___/ __ `__ \\/ _ \\/ ___/\u001b[0m")
	println("\u001b[38;5;31m / __  /  __/ /  / / / / / /  __(__  ) \u001b[0m")
	println("\u001b[38;5;31m/_/ /_/\\___/_/  /_/ /_/ /_/\\___/____/  \u001b[0m")

	fmt.Println()
	color.Blue("By Hades, inst: @ctpe")
	fmt.Println()

	for {
		var TPM string
		G.Print("Enter the number of Gorountines: ")
		fmt.Scanln(&TPM)
		DeleteLine()

		if _, err := strconv.Atoi(TPM); err == nil && TPM != "0" && !strings.Contains(TPM, "-") {
			_int64, _ := strconv.ParseInt(TPM, 0, 64)
			ThreadsPerMoment = int(_int64)
			break
		} else {
			R.Println("Enter a correct number")
			time.Sleep(time.Second * 2)
			DeleteLine()
		}
	}

	max = ThreadsPerMoment + 2
	runtime.GOMAXPROCS(max)

	G.Print("Do you want a Delay(Sleep) ? [y/n]: ")
	fmt.Scanln(&choice)
	DeleteLine()

	if strings.ToLower(choice) == "y" {
		for {
			var SLP string
			G.Print("Enter the time of the delay(MilliSeconds)[1 sec = 1000]: ")
			fmt.Scanln(&SLP)
			DeleteLine()

			if _, err := strconv.Atoi(SLP); err == nil && SLP != "0" && !strings.Contains(SLP, "-") {
				_int64, _ := strconv.ParseInt(SLP, 0, 64)
				sLPTime = int(_int64)
				break
			} else {
				R.Println("Enter a correct number")
				time.Sleep(time.Second * 2)
				DeleteLine()
			}
		}
	}

	G.Print("Do you want a Timeout ? [y/n]: ")
	fmt.Scanln(&choice)
	DeleteLine()

	if strings.ToLower(choice) == "y" {
		for {
			var TMT string
			G.Print("Enter the time of the Timeout(MilliSeconds): ")
			fmt.Scanln(&TMT)
			DeleteLine()

			if _, err := strconv.Atoi(TMT); err == nil && TMT != "0" && !strings.Contains(TMT, "-") {
				_int64, _ := strconv.ParseInt(TMT, 0, 64)
				timeOut = int(_int64)
				break
			} else {
				R.Println("Enter a correct number")
				time.Sleep(time.Second * 2)
				DeleteLine()
			}
		}
	}

	G.Print("Do you wanna hunt or swap the username ? [H/S]: ")
	fmt.Scanln(&choice)
	DeleteLine()

	if strings.ToLower(choice) == "h" {
		swap = false
	}

	G.Print("Enable Logging (\"The Path that you run Hermes from\"/Hermes.log) ? [y/n]: ")
	fmt.Scanln(&choice)
	DeleteLine()

	if strings.ToLower(choice) == "y" {
		_log = true
		f, ferror = os.OpenFile("Hermes.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		logger = log.New(f, "Hermes: ", log.LstdFlags)
	}

	// G.Print("Login with Instagram App API[a] or Web API[w]: ")
	// fmt.Scanln(&choice)
	// DeleteLine()
	WebAPI := "a"

	for {
		var TAU string
		G.Print("Enter the username: ")
		fmt.Scanln(&TAU)
		DeleteLine()
		receiverUS = TAU
		var TAP string
		G.Print("Enter the password: ")
		fmt.Scanln(&TAP)
		DeleteLine()
		waiting := true
		var res HttpResponse
		go func() {
			if strings.ToLower(WebAPI) == "a" {
				res = login(TAU, TAP, "", false, InstaAPI, 60*1000)
			} else { // fix
				res = LoginWebInstagram(TAU, TAP, "", 60*1000)
			}
			waiting = false
		}()

		for {
			if waiting {
				color.Yellow("Logging In .")
				time.Sleep(time.Millisecond * 400)
				DeleteLine()
				color.Yellow("Logging In ..")
				time.Sleep(time.Millisecond * 400)
				DeleteLine()
				color.Yellow("Logging In ...")
				time.Sleep(time.Millisecond * 400)
				DeleteLine()
			} else {
				break
			}
		}

		flag := false
		if strings.ToLower(WebAPI) == "a" {
			flag = strings.Contains(res.Body, "logged_in_user")
		} else {
			flag = strings.Contains(res.Body, "authenticated\": true") || strings.Contains(res.Body, "userId")
		}
		if flag {
			receiverProfile, _ = GetProfile(res.Cookies, InstaAPI, 1000*60)
			if receiverProfile != nil {
				color.Green("Logged In Successfully")
				time.Sleep(time.Second * 2)
				DeleteLine()
				receiverCookies = res.Cookies
				CookiesMap := make(map[string]string)
				for i := 0; i < len(receiverCookies); i++ {
					CookiesMap[receiverCookies[i].Name] = receiverCookies[i].Value
				}
				receiverCookiesMap = CookiesMap
				break
			} else {
				color.Red("There's something wrong!")
				time.Sleep(time.Second * 2)
				DeleteLine()
				G.Print("Do you wanna try again? [y/n]: ")
				fmt.Scanln(&choice)
				if strings.ToLower(choice) != "y" {
					end(2)
				} else {
					DeleteLine()
					continue
				}
			}
		} else {
			color.Red("There's something wrong!")
			time.Sleep(time.Second * 2)
			DeleteLine()
			G.Print("Do you wanna try again? [y/n]: ")
			fmt.Scanln(&choice)
			if strings.ToLower(choice) != "y" {
				end(2)
			} else {
				DeleteLine()
				continue
			}
		}
	}

	G.Print("Do you wanna change the target username from here? [y/n]: ")
	fmt.Scanln(&choice)
	DeleteLine()

	if strings.ToLower(choice) == "y" {
		for {
			G.Print("Enter the username: ")
			fmt.Scanln(&target)
			DeleteLine()
			var TAP string
			G.Print("Enter the password: ")
			fmt.Scanln(&TAP)
			DeleteLine()
			waiting := true
			var res HttpResponse
			go func() {
				if strings.ToLower(WebAPI) == "a" {
					res = login(target, TAP, "", false, InstaAPI, 1000*60)
				} else {
					res = LoginWebInstagram(target, TAP, "", 60*1000)
				}
				waiting = false
			}()

			for {
				if waiting {
					color.Yellow("Logging In .")
					time.Sleep(time.Millisecond * 400)
					DeleteLine()
					color.Yellow("Logging In ..")
					time.Sleep(time.Millisecond * 400)
					DeleteLine()
					color.Yellow("Logging In ...")
					time.Sleep(time.Millisecond * 400)
					DeleteLine()
				} else {
					break
				}
			}

			flag := false
			if strings.ToLower(WebAPI) == "a" {
				flag = strings.Contains(res.Body, "logged_in_user")
			} else {
				flag = strings.Contains(res.Body, "authenticated\": true") || strings.Contains(res.Body, "userId")
			}
			if flag {
				twoMod = true
				color.Green("Logged In Successfully")
				time.Sleep(time.Second * 2)
				DeleteLine()
				G.Print("Enter the new username(Make sure it's available): ")
				fmt.Scanln(&changeTo)
				DeleteLine()
				TargetCookies = res.Cookies
				CookiesMap := make(map[string]string)
				for i := 0; i < len(TargetCookies); i++ {
					CookiesMap[TargetCookies[i].Name] = TargetCookies[i].Value
				}
				TargetCookiesMap = CookiesMap
				break
			} else {
				color.Red("There's something wrong!")
				time.Sleep(time.Second * 2)
				DeleteLine()
				G.Print("Do you wanna try again? [y/n]: ")
				fmt.Scanln(&choice)
				if strings.ToLower(choice) != "y" {
					DeleteLine()
					break
				}
				DeleteLine()
				continue
			}
		}
	} else {
		G.Print("Enter the target's username: ")
		fmt.Scanln(&target)
		DeleteLine()
	}

	flag, r, _ := CheckWebInstagram(target, receiverCookiesMap["sessionid"], "", 60000)
	if flag == 0 && r != "" {
		status, _, _ := CheckUserName(target, "", receiverCookiesMap["csrftoken"], 0, InstaAPI)
		if status == 0 {
			res, _ := Edit(guid, receiverCookies, target, "", "By Hermes Tool @ctpe", "https://i.instagram.com/ctpe", "Hi", "", "", receiverCookiesMap["ds_user_id"], receiverCookiesMap["csrftoken"], InstaAPI, 60000, receiverProfile)
			if strings.Contains(res.Body, "\"user\":") && strings.Contains(res.Body, "\"status\": \"ok\"") {
				hunted = true
				start = false
				unleash = false
				editingStarted = false
				end(0)
			}
		} else if status == 1 {
			day = true
		} else {
			banned = true
		}
	}

	if twoMod {
		max = ThreadsPerMoment + 3
	}
	runtime.GOMAXPROCS(max)

	if twoMod {
		go changeUsername()
	}

	go startThreads(ThreadsPerMoment)

	for {
		if startedThreads != ThreadsPerMoment {
			println("\u001b[38;5;50minitiating all the Gorountines : \u001b[0m: ", startedThreads)
			time.Sleep(time.Millisecond * 25)
			DeleteLine()
			continue
		}

		println("\u001b[38;5;50mall the Gorountines have initiated successfully\u001b[0m: ", startedThreads)
		time.Sleep(time.Millisecond * 500)
		DeleteLine()
		start = true
		println("\u001b[38;5;242mPress any key to start...\u001b[0m")
		fmt.Scanln()
		DeleteLine()
		time.Sleep(time.Millisecond * 10)
		go func() {
			for {
				if started && start && !editingStarted {
					unleash = true
					break
				}
			}
		}()
		go calculate()
		progress()

	}
}
