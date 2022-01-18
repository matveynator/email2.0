package main

import (
  "crypto/tls"
  "flag"
  "log"
  "os"
  "rigel/packages/smtp"
  "rigel/packages/smtpd"
)

var sslCertificatePem = []byte(`-----BEGIN CERTIFICATE-----
MIIFqDCCBJCgAwIBAgISA9t4D0HQetQBdFRqLCY7RQrvMA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xOTAxMDEwODQ5NDVaFw0x
OTA0MDEwODQ5NDVaMBkxFzAVBgNVBAMTDm1haWwuY29wdGVyLnJ1MIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxf9VJ0cJc8RVm0KBlFFTC6lA6tATi7yn
Jgy9afVi/c3Qlvx7HIRC8jgaK4A9sc5817PiAalrzrCLRaTejxo7LUO8A2DCzBZe
3F9/UrNQGbCDF+iXiFjOKah/L+kui03oCcuGRBsxytBT9Z7K/Ys99R5IwMjANgzf
fLM1jpVoZjObC0vXbKaeQb756WmaiLBcmeenRuegb5V1XCcQsGoN0MbjMMVOXpF2
MlbDP55lQPnHakZogwo7qbVoyf0xwfmA1PB2CfeHRxwZ0kR0AUMfEXS5Jy6wBLbm
XAU6HO/xZPLH/OhWc7QXr7N58dVg0SLYo7U0WUeAwqgVKGFB3fNhFwIDAQABo4IC
tzCCArMwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEF
BQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBS8LhrOA+LzkrypHQ7h1nogxQxz
DTAfBgNVHSMEGDAWgBSoSmpjBH3duubRObemRWXv86jsoTBvBggrBgEFBQcBAQRj
MGEwLgYIKwYBBQUHMAGGImh0dHA6Ly9vY3NwLmludC14My5sZXRzZW5jcnlwdC5v
cmcwLwYIKwYBBQUHMAKGI2h0dHA6Ly9jZXJ0LmludC14My5sZXRzZW5jcnlwdC5v
cmcvMG0GA1UdEQRmMGSCDm1haWwuY29wdGVyLnJ1gg9tYWlsLmNvcHRlcnMucnWC
E21haWwub3Zlcm1vYmlsZS5uZXSCGW1haWwucGVyZnRvcmFuLWFyY2hpdmUucnWC
EW1haWwuemFiaXlha2EubmV0MEwGA1UdIARFMEMwCAYGZ4EMAQIBMDcGCysGAQQB
gt8TAQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5cHQub3Jn
MIIBBAYKKwYBBAHWeQIEAgSB9QSB8gDwAHYA4mlLribo6UAJ6IYbtjuD1D7n/nSI
+6SPKJMBnd3x2/4AAAFoCNGrWAAABAMARzBFAiEAusaXCCxLtdQH7b9gpxPeC/+U
mExSMbyVcU8BlQC9t8ICIFO4iWmqubnnGZbdQDp9M/j7TEf65QVNKvD2BsZLJOQs
AHYAKTxRllTIOWW6qlD8WAfUt2+/WHopctykwwz05UVH9HgAAAFoCNGrVwAABAMA
RzBFAiEA9toTlBrgxsmTLSCU90qUBVLe03IZltLEbJ6zbqximAoCIBBKz588jGGT
gJ1f5Iwz4mYRMfFXa5yCYf+Tad8HJ8TFMA0GCSqGSIb3DQEBCwUAA4IBAQAH2XSC
flx6nqEptyc8pUY1vGh+UaWUQd2tR+hK6DM8Ijq+oOLI/p3Hao7Ixj6Iv4my6dYx
DXCBQoKiqd1MEwyVh7GgcTcSgpsG6FwjJvfd8CAQ5OOpwq5a/crLRB470qm0/Ef+
tqgickji4Am+pP4xRoFsGpzTSTUZlKnBwBiOpjboaAiBQkPsnYUa8I42kWTeWS4d
AXr+5pnY+L6XLx+uQJ7dUZ0Xh9xUGPJZUXwruEWE+Rmc+b9nzEQIsqfewWVhi1o8
s4WFj+UHUKzooU8NQVVj1de2pMdWaCiyEHQwPapLJGANlkg+gDiEv0MrPKIRE80i
NWgXuwRz5ZrxqEo9
-----END CERTIFICATE-----`)

var sslKeyPem = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDF/1UnRwlzxFWb
QoGUUVMLqUDq0BOLvKcmDL1p9WL9zdCW/HschELyOBorgD2xznzXs+IBqWvOsItF
pN6PGjstQ7wDYMLMFl7cX39Ss1AZsIMX6JeIWM4pqH8v6S6LTegJy4ZEGzHK0FP1
nsr9iz31HkjAyMA2DN98szWOlWhmM5sLS9dspp5BvvnpaZqIsFyZ56dG56BvlXVc
JxCwag3QxuMwxU5ekXYyVsM/nmVA+cdqRmiDCjuptWjJ/THB+YDU8HYJ94dHHBnS
RHQBQx8RdLknLrAEtuZcBToc7/Fk8sf86FZztBevs3nx1WDRItijtTRZR4DCqBUo
YUHd82EXAgMBAAECggEABP50smHrTh00n47k383RT2j8dy+6XnrqqF4H5QVIcuhf
C3/gxw5a9esOVeyNIc/4fCRQXgRc8MCpMp9+8ZMSzQh5VIh7QVSLHfnWp0pYid1W
4SJ/t/Otd4WFd7rk7qSPZrfYch1RezEX/Qj9S7nYXTdfVGV726ElfeqzPh5snK9D
LPVv0W/ikvBU9CvJlCEUS/L7SL0FmtwlmcJ94DOcepHwNGHWe+cU0OMa/JhuunQE
wBE2HdNOcyC6O90ksOMSHFfW+hiiKJcmmyoauQ2l7mjrqEdpIE4Hmpa5O908vA4P
v49tSVlCslwt3nwprqHHdcGb5ZHkspU052VWtzdjaQKBgQDlI+7HlalPyC65LoSU
aAnTjfZucyvKPgttJAvME3fhgrPpQNZlCHTDubCDhUWYiWNijmZgeMVDyoZVS1N8
NN8bl1hcsN9eKH+NA7nx889c1MpmDXo4r4JQeXUUHSY6X9uGgh5+fqoiwxy1JZ7u
vNWIA8smsiZpY6KWi8VJywsw2wKBgQDdNNvHsKCxTyTKLTqNCDvrOtMkHi3Ejn/k
7FxercBavOV6vUjButhJyLq2GEm6JoN35QS1Bi1iqjDg6mTcazk3BnfWJParVJz7
9F/IB4J5SMSkYFCqyzExR1Uro2maUt38AGoAuQT+bhRVMEDzbW+G5q3c11OJl2iw
2eZxtzU3dQKBgCzFUZFTj6pT/bUW/raUgV8BfOXlwOeaKddgVKHCKAk65XYswfcp
qM7ZSEDaWFfOeEm4cw5kan6tYoPl3OEG35TfhFdQA8S8+vcNhFZfAeQse4NnHLtY
p4ibwqF0dJSxSA5G/DhQ/WMfZkuKlzwkT0BtJVNhOZob6peppZmef4hDAoGAbw+C
6Rd9Foit5/QdWYGw08GNEK02PWFuRPmGxuJlmSkN7jnqtZmhzinB1HsNSTDdAO0z
F9AqKUdZkxMb4K7U4xOURyf30L2Cs91V2ZArqcknMYBJ//ZUlHFECczZ0GmamlN6
5TH/l96cxsibU5y2Sfy3fhF+F661GVXNpXpedaECgYB0/fzOuQK0foYXLsBJYZFK
cfWvloTy40XLzc9r42gc6dmsTc3ZgjzOtu7MSqGSDvB6ORk+H6nJ4j6uUBsYhObj
JUa7rkQMqX8VjtVXwyHMDe+r60OrNrO5iOJxcoJwJYXOHhOQ9QMHUUMKn5WHp3ov
7YdVaiVabQkTOwhde+axMw==
-----END PRIVATE KEY-----`)

//optional arguments to proxy all incoming mail to smtp server
var ListenIP, ListenPort, Domain, SmartHost, SmartPort, Version string

func AuthUser (peer smtpd.Peer, username, password string ) bool {
  log.Println("login: " + username)
  log.Println("pass: " + password)
  if username=="test@rigel.email" && password=="l45vegas" { 
    log.Println("Notice: auth succeded.")
    return true
  } else {
    log.Println("Error: auth failed.")
    return false
  }
}

func handler(peer smtpd.Peer, env smtpd.Envelope) error {
  //check it PlainAuth required to smarthost?
  /*if (SmartLogin!="" && SmartPass!="") {
    return smtp.SendMail(
      SmartHost+":"+SmartPort,
      smtp.PlainAuth("", SmartLogin, SmartPass, SmartHost+":"+SmartPort),
      env.Sender,
      env.Recipients,
      env.Data,
    )
  }
  */
    return smtp.SendMail(
      SmartHost+":"+SmartPort,
      nil,
      env.Sender,
      env.Recipients,
      env.Data,
    )

}

func main() {

	flagVersion := flag.Bool("version", false, "Output version information")
  flag.StringVar( &ListenIP, "listenip", "0.0.0.0", "Hostname or IP to listen on, 0.0.0.0 is default.")
  flag.StringVar( &ListenPort, "listenport", "25","Port to listen, 25 SMTP is default.")
  flag.StringVar( &SmartHost, "smarthost", "127.0.0.1", "Hostname or IP of the smtp smarthost to forward all incoming mail to, 127.0.0.1 is default.")
  flag.StringVar( &SmartPort, "smartport", "125","Port of the smtp smarthost to forward all incoming mail to, 125 is default.")
  flag.StringVar( &Domain, "domain", "localhost", "Domain to receive mail.")
  flag.Parse()

	if *flagVersion  {
		if Version != "" {
			log.Println("Version:", Version)
		}
		os.Exit(0)
	}

	log.Println("Rigel E-mail 2.0 ver:"+Version+" is listening on "+ListenIP+":"+ListenPort+ " as "+Domain+" and forwarding all mail to "+SmartHost+":"+SmartPort)

  server := &smtpd.Server{
    WelcomeMessage:   "Rigel E-mail 2.0 ESMTP ready.",
    Handler:          handler,
    Authenticator:    AuthUser,
    Hostname:         Domain,
  }

  certificate, err := tls.X509KeyPair(sslCertificatePem, sslKeyPem)
  if err != nil {
    log.Println("Cert load failed:", err)
  }
  server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{certificate},}
  server.ListenAndServe(ListenIP+":"+ListenPort)
}
