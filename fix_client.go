// Copyright 2025-present Coinbase Global, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/quickfixgo/quickfix"
)

type FixApplication struct {
	ApiKey       string
	ApiSecret    string
	Passphrase   string
	TargetCompId string
	PortfolioId  string
	SessionId    quickfix.SessionID
}

func (a *FixApplication) OnCreate(sessionId quickfix.SessionID) {
	log.Println("Session created:", sessionId)
	a.SessionId = sessionId
}

func (a *FixApplication) OnLogon(sessionId quickfix.SessionID) {
	log.Println(" Logged in:", sessionId)
	a.SessionId = sessionId

	order := createOrderMessage("ETH-USD", "LIMIT", "BUY", "0.0015", "1001", a.PortfolioId)
	log.Println("Raw FIX Message:", order.String())

	// Send using session ID
	err := quickfix.SendToTarget(order, sessionId)
	if err != nil {
		log.Println("Failed to send order:", err)
	} else {
		log.Println("Order sent successfully!")
	}
}

func (a *FixApplication) OnLogout(sessionId quickfix.SessionID) {
	log.Println("Logged out:", sessionId)
}

func (a *FixApplication) ToAdmin(msg *quickfix.Message, sessionId quickfix.SessionID) {
	log.Println("Sending Admin:", msg)

	msgType, _ := msg.Header.GetString(quickfix.Tag(35))
	if msgType == "A" { // Logon Message
		timestamp := time.Now().UTC().Format("20060102-15:04:05.000")
		seqNum := "1"

		// Generate HMAC signature for authentication
		signature := sign(timestamp, "A", seqNum, a.ApiKey, a.TargetCompId, a.Passphrase, a.ApiSecret)

		// Add all required authentication fields
		msg.Body.SetField(quickfix.Tag(1), quickfix.FIXString(a.PortfolioId))  // Account (Portfolio ID)
		msg.Body.SetField(quickfix.Tag(96), quickfix.FIXString(signature))     // RawData (HMAC Signature)
		msg.Body.SetField(quickfix.Tag(554), quickfix.FIXString(a.Passphrase)) // Password
		msg.Body.SetField(quickfix.Tag(9406), quickfix.FIXString("Y"))         // DropCopyFlag (default "Y")
		msg.Body.SetField(quickfix.Tag(9407), quickfix.FIXString(a.ApiKey))    // Access Key (API Key)
	}
}

func (a *FixApplication) FromAdmin(msg *quickfix.Message, sessionId quickfix.SessionID) quickfix.MessageRejectError {
	log.Println("Received Admin:", msg)
	return nil
}

func (a *FixApplication) ToApp(msg *quickfix.Message, sessionId quickfix.SessionID) error {
	log.Println("Sending App:", msg)
	return nil
}

func (a *FixApplication) FromApp(msg *quickfix.Message, sessionId quickfix.SessionID) quickfix.MessageRejectError {
	log.Println("Received App:", msg)

	msgType, _ := msg.Header.GetString(quickfix.Tag(35))
	if msgType == "8" { // Execution Report
		a.processExecutionReport(msg)
	}

	return nil
}

func (a *FixApplication) processExecutionReport(msg *quickfix.Message) {
	var execType, orderID, clOrdID, side, quantity quickfix.FIXString

	// Extract values from the message body
	msg.Body.GetField(quickfix.Tag(150), &execType) // ExecType
	msg.Body.GetField(quickfix.Tag(37), &orderID)   // OrderID
	msg.Body.GetField(quickfix.Tag(11), &clOrdID)   // Client Order ID
	msg.Body.GetField(quickfix.Tag(54), &side)      // Side (Buy/Sell)
	msg.Body.GetField(quickfix.Tag(38), &quantity)  // Order Quantity

	// Log execution report details
	log.Printf("Execution Report: OrderID=%s ClOrdID=%s Side=%s Quantity=%s ExecType=%s",
		orderID, clOrdID, side, quantity, execType)
}

// LoadFIXConfig loads the FIX configuration file
func LoadFIXConfig(path string) (*quickfix.Settings, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return quickfix.ParseSettings(file)
}

// sign generates a FIX authentication signature
func sign(timestamp, msgType, seqNum, accessKey, targetCompID, passphrase, secret string) string {
	message := timestamp + msgType + seqNum + accessKey + targetCompID + passphrase
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func createOrderMessage(symbol, ordType, side, quantity, limitPrice, portfolioId string) *quickfix.Message {
	order := quickfix.NewMessage()

	// Header fields (standard FIX header)
	order.Header.SetField(quickfix.Tag(35), quickfix.FIXString("D"))                                              // MsgType = 'D'
	order.Header.SetField(quickfix.Tag(49), quickfix.FIXString(os.Getenv("SVC_ACCOUNTID")))                       // SenderCompID
	order.Header.SetField(quickfix.Tag(56), quickfix.FIXString("COIN"))                                           // TargetCompID
	order.Header.SetField(quickfix.Tag(52), quickfix.FIXString(time.Now().UTC().Format("20060102-15:04:05.000"))) // SendingTime

	// Body fields (order data)
	clientOrderId := fmt.Sprintf("%d", time.Now().UnixNano())
	order.Body.SetField(quickfix.Tag(1), quickfix.FIXString(portfolioId))    // Account (Portfolio ID)
	order.Body.SetField(quickfix.Tag(11), quickfix.FIXString(clientOrderId)) // ClOrdID
	order.Body.SetField(quickfix.Tag(55), quickfix.FIXString(symbol))        // Symbol

	// Order Type, TimeInForce, Price, TargetStrategy
	if ordType == "LIMIT" {
		order.Body.SetField(quickfix.Tag(40), quickfix.FIXString("2")) // OrdType = Limit
		order.Body.SetField(quickfix.Tag(59), quickfix.FIXString("1")) // TimeInForce = GTC (example)
		order.Body.SetField(quickfix.Tag(44), quickfix.FIXString(limitPrice))
		order.Body.SetField(quickfix.Tag(847), quickfix.FIXString("L")) // TargetStrategy = Limit
	} else if ordType == "MARKET" {
		order.Body.SetField(quickfix.Tag(40), quickfix.FIXString("1"))  // OrdType = Market
		order.Body.SetField(quickfix.Tag(59), quickfix.FIXString("3"))  // TimeInForce = IOC
		order.Body.SetField(quickfix.Tag(847), quickfix.FIXString("M")) // TargetStrategy = Market
	}

	// Side
	if side == "BUY" {
		order.Body.SetField(quickfix.Tag(54), quickfix.FIXString("1")) // Side = Buy
	} else {
		order.Body.SetField(quickfix.Tag(54), quickfix.FIXString("2")) // Side = Sell
	}

	// Order Quantity
	order.Body.SetField(quickfix.Tag(38), quickfix.FIXString(quantity))

	// Additional logging
	log.Printf("Order Message: ClOrdID=%s Symbol=%s Side=%s Quantity=%s Price=%s",
		clientOrderId, symbol, side, quantity, limitPrice)

	log.Println("Full FIX Message:", order.String())
	return order
}

func main() {
	// Load FIX configuration (ensure 'fix.cfg' exists)
	settings, err := LoadFIXConfig("fix.cfg")
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	app := &FixApplication{
		ApiKey:       os.Getenv("ACCESS_KEY"),
		ApiSecret:    os.Getenv("SIGNING_KEY"),
		Passphrase:   os.Getenv("PASSPHRASE"),
		TargetCompId: "COIN",
		PortfolioId:  os.Getenv("PORTFOLIO_ID"),
	}

	storeFactory := quickfix.NewMemoryStoreFactory()
	logFactory := quickfix.NewScreenLogFactory()
	initiator, err := quickfix.NewInitiator(app, storeFactory, settings, logFactory)
	if err != nil {
		log.Fatal("Failed to create initiator:", err)
	}

	// Start FIX session
	err = initiator.Start()
	if err != nil {
		log.Fatal("Failed to start FIX session:", err)
	}

	// Keep the application running
	select {}
}
