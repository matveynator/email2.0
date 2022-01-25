package mailbox

import (
	"log"
	"database/sql"
	// import Genji as a blank import
	_ "github.com/genjidb/genji/driver"
)

type Email struct {
	ID int64
	From,To,Subject,Date,Data string
	Unread bool
}

func GetNewMail(email, mailbox string) ([]Email, error) {

	db, err := sql.Open("genji", email + "_genjidb")
	if err != nil {
		log.Fatal(err)
	}

	defer db.Close()

	rows, err := db.Query("SELECT * FROM ? WHERE unread = 'true'", mailbox)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// An album slice to hold data from returned rows.
	var emails []Email

	// Loop through rows, using Scan to assign column data to struct fields.
	for rows.Next() {
		var email Email
		if err := rows.Scan(&email.ID, &email.Subject, &email.From,
		&email.Date, &email.Data, &email.Unread); err != nil {
			return nil, err
		}
		emails = append(emails, email)
	}
	if err = rows.Err(); err != nil {
		return emails, err
	}
	return emails, nil
}
