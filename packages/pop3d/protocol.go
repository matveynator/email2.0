package pop3d 

import (
	"bytes"
	"encoding/base64"
	"strings"
)

type command struct {
	line   string
	action string
	fields []string
	params []string
}

func parseLine(line string) (cmd command) {

	cmd.line = line
	cmd.fields = strings.Fields(line)

	if len(cmd.fields) > 0 {

		cmd.action = strings.ToUpper(cmd.fields[0])

		if len(cmd.fields) > 1 {

			// Account for some clients breaking the standard and having
			// an extra whitespace after the ':' character. Example:
			//
			// MAIL FROM: <test@example.org>
			//
			// Should be:
			//
			// MAIL FROM:<test@example.org>
			//
			// Thus, we add a check if the second field ends with ':'
			// and appends the rest of the third field.

			if cmd.fields[1][len(cmd.fields[1])-1] == ':' && len(cmd.fields) > 2 {
				cmd.fields[1] = cmd.fields[1] + cmd.fields[2]
				cmd.fields = cmd.fields[0:2]
			}

			cmd.params = strings.Split(cmd.fields[1], ":")

		}

	}

	return

}

func (session *session) handle(line string) {

	cmd := parseLine(line)
	//log.Printf("%#v", cmd)

	// Commands are dispatched to the appropriate handler functions.
	// If a network error occurs during handling, the handler should
	// just return and let the error be handled on the next read.

	switch cmd.action {

	case "USER":
		session.handleLIST(cmd)
		return

	case "PASS":
		session.handleLIST(cmd)
		return

	case "STAT":
		session.handleLIST(cmd)
		return

	case "LIST":
		session.handleLIST(cmd)
		return

	case "UIDL":
		session.handleLIST(cmd)
		return

	case "TOP":
		session.handleLIST(cmd)
		return

	case "RETR":
		session.handleLIST(cmd)
		return

	case "DELE":
		session.handleLIST(cmd)
		return

	case "QUIT":
		session.handleQUIT(cmd)
		return

		session.reply(502, "Unsupported command.")

	}
}

func (session *session) handleLIST(cmd command) {
	session.reset()
	session.reply(250, "Go ahead")
	return
}

func (session *session) handleRSET(cmd command) {
	session.reset()
	session.reply(250, "Go ahead")
	return
}

func (session *session) handleQUIT(cmd command) {
	session.reply(221, "OK, bye")
	session.close()
	return
}

func (session *session) handleAUTH(cmd command) {
	if len(cmd.fields) < 2 {
		session.reply(502, "Invalid syntax.")
		return
	}
	if session.server.Authenticator == nil {
		session.reply(502, "AUTH not supported.")
		return
	}
	if session.peer.HeloName == "" {
		session.reply(502, "Please introduce yourself first.")
		return
	}
	if !session.tls {
		session.reply(502, "Cannot AUTH in plain text mode. Use STARTTLS.")
		return
	}
	mechanism := strings.ToUpper(cmd.fields[1])

	username := ""
	password := ""

	switch mechanism {

	case "PLAIN":

		auth := ""

		if len(cmd.fields) < 3 {
			session.reply(334, "Give me your credentials")
			if !session.scanner.Scan() {
				return
			}
			auth = session.scanner.Text()
		} else {
			auth = cmd.fields[2]
		}

		data, err := base64.StdEncoding.DecodeString(auth)

		if err != nil {
			session.reply(502, "Couldn't decode your credentials")
			return
		}

		parts := bytes.Split(data, []byte{0})

		if len(parts) != 3 {
			session.reply(502, "Couldn't decode your credentials")
			return
		}

		username = string(parts[1])
		password = string(parts[2])

	case "LOGIN":

		encodedUsername := ""

		if len(cmd.fields) < 3 {
			session.reply(334, "VXNlcm5hbWU6")
			if !session.scanner.Scan() {
				return
			}
			encodedUsername = session.scanner.Text()
		} else {
			encodedUsername = cmd.fields[2]
		}

		byteUsername, err := base64.StdEncoding.DecodeString(encodedUsername)

		if err != nil {
			session.reply(502, "Couldn't decode your credentials")
			return
		}

		session.reply(334, "UGFzc3dvcmQ6")

		if !session.scanner.Scan() {
			return
		}

		bytePassword, err := base64.StdEncoding.DecodeString(session.scanner.Text())

		if err != nil {
			session.reply(502, "Couldn't decode your credentials")
			return
		}

		username = string(byteUsername)
		password = string(bytePassword)

	default:

		session.reply(502, "Unknown authentication mechanism")
		return

	}

	auth := session.server.Authenticator(session.peer, username, password)
	if auth == true {
		session.peer.Username       = username
		session.peer.Password       = password
		session.peer.Authenticated  = true
		session.reply(235, "OK, you are now authenticated")
	} else {
		session.peer.Authenticated  = false
		//session.error()
		return
	}
}
