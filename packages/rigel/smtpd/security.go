//Package security implements varios SMTP, DNS and MAILBOX AUTH checks.
//Spf section - provides various DNS functions to test if to relay mail from certain IPs. 
//Mailbox section - provides various smtpd mailbox related security checks like login/password and others. 
package smtpd

import (
  "net"
  "log"
  "strings"
  "errors"
  "github.com/miekg/dns"
  "crypto/tls"
  "rigel/smtp"
)


//Fuction recovery() implements recovery actions when calling last defer function on panic situation (fatal errors). And proceeding normally instead of crashing.
func recovery() {
  if r := recover(); r != nil {
    log.Println("Recovered from panic: ", r)
  }
}

//Check that string array does hold uniq strings before inserting next variant. 
func CheckStringInArray(str string, list []string) bool {
  for _, v := range list {
    if v == str {
      return true
    }
  }
  return false
}

//***Spf section start***

//Function to lookup array of A DNS records for required domain.
func LookupValidAIPs(domain string) (iplist []string, err error) {
  defer recovery()
  //parse A records
  aIPs, err := net.LookupHost(domain)
  if err == nil {
    for _, target := range aIPs {
      ip := net.ParseIP(target)
      if ip != nil {
        if !CheckStringInArray(ip.String(), iplist) {
          iplist = append(iplist, ip.String())
        }
      }
    }
  } else {
    //we want to evaluate only timeout and permanent DNS errors. 
    if err.(net.Error).Timeout() {
      err = errors.New("DNS host lookup time out.")
    } else if err.(net.Error).Temporary() {
      err = errors.New("DNS host lookup temporary error.")
    } else {
      err = nil
    }
  }
  return 
}

//Function to lookup array of MX DNS records for required domain.
func LookupValidMXIPs(domain string) (iplist []string, err error) {
  defer recovery()
  //parse MX records
  mxIPs, err := net.LookupMX(domain)
  if err == nil {
    for _, targetMX := range mxIPs {
      aIPs, err := net.LookupHost(targetMX.Host)
      if err == nil {
        for _, targetA := range aIPs {
          ip := net.ParseIP(targetA)
          if ip != nil {
            if !CheckStringInArray(ip.String(), iplist) {
              iplist = append(iplist, ip.String())
            }
          }
        }
      } else {
        //we want to evaluate only timeout and permanent DNS errors.
        if err.(net.Error).Timeout() {
          err = errors.New("DNS mx lookup time out.")
        } else if err.(net.Error).Temporary() {
          err = errors.New("DNS mx lookup temporary error.")
        } else {
          err = nil
        }
      }
    }
  } else {
    //we want to evaluate only timeout and permanent DNS errors.
    if err.(net.Error).Timeout() {
      err = errors.New("DNS mx lookup time out.")
    } else if err.(net.Error).Temporary() {
      err = errors.New("DNS mx lookup temporary error.")
    } else {
      err = nil
    }
  }
  return 
}

//Function to lookup array of SPF TXT DNS records for required domain.
func (session *session) LookupValidSPFIPs(domain string) (iplist []string, err error) {

  defer recovery()

  //parse SPF records
  config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")

  //label for goto function
  c := dns.Client{}
  //Suppressing multiple outstanding queries
  c.SingleInflight = true
  m := dns.Msg{}
  m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
  m.RecursionDesired = true
  //m.SetEdns0(4096, false) = false disables DNSEC verification.
  m.SetEdns0(8192, false)
  //r, _, err := c.Exchange(&m, "8.8.8.8:53")
  r, _, err := c.Exchange(&m, net.JoinHostPort(config.Servers[0], "53"))
  // log.Printf("%#v", r)
  if err != nil {
    //verify timout errors
    _, err = net.LookupTXT(dns.Fqdn(domain))
    if err.(net.Error).Timeout() {
      err = errors.New("DNS spf lookup time out.")
    } else if err.(net.Error).Temporary() {
      err = errors.New("DNS spf lookup temporary error.")
    } else {
      err = errors.New("DNS spf lookup error")
    }
    log.Println(err)
    return
  } else if r.Rcode != dns.RcodeSuccess {
    log.Println("Invalid answer after TXT query for " + domain)
  } else { 
    for _, answer := range r.Answer {
      txtrecord := ""
      if answer.(dns.RR) == answer.(*dns.TXT)  {
        for _, part_record := range answer.(*dns.TXT).Txt {
          //join all devided SPF records in one record (stupid protocol 255 length)
          txtrecord += part_record
        }
        //log.Println("%#v", "RRRRRAAAAAWWWW: " + txtrecord)
        if strings.HasPrefix(txtrecord, "v=spf") {

          //split all current records with whitespaces and parse them one by one
          records := strings.Split(txtrecord, " ")
          for _, record := range records {

            //gather all redirects and process them recursivelly:
            if strings.HasPrefix(record, "redirect=") {
              target := strings.Split(record, "redirect=")
              if len(target[1]) != 0 {
                //loop protection (check if we allready visited target[1])
                if CheckStringInArray(target[1], session.peer.LoopCheck) {
                  //error - loop in dns detected. 
                  err = errors.New("Redirect loop detected in DNS SPF record at hop to -> "+domain)
                  //log.Println(err.Error())
                  return
                } else {
                  //add target to loop aray to check next time
                  session.peer.LoopCheck = append(session.peer.LoopCheck, target[1])
                  //get reqursivelly
                  rawspfips,err := session.LookupValidSPFIPs(target[1]) 
                  if err==nil {
                    for _, spfip := range rawspfips {
                      iplist = append(iplist, spfip)
                    }
                  } else {
                    //log.Println(err.Error())
                    return iplist,err 
                  }
                }
              }
            }

            //gather all includes and process them recursivelly:
            if strings.HasPrefix(record, "include:") {
              target := strings.Split(record, "include:")
              if len(target[1]) != 0 {
                //loop protection (check if we allready visited target[1])
                if CheckStringInArray(target[1], session.peer.LoopCheck) {
                  //error - loop in dns detected. 
                  err = errors.New("Include loop detected in DNS SPF record at hop to -> "+domain)
                  log.Println(err.Error())
                  return
                } else {
                  //add target to loop aray to check next time
                  session.peer.LoopCheck = append(session.peer.LoopCheck, target[1])
                  //get reqursivelly
                  rawspfips,err := session.LookupValidSPFIPs(target[1])
                  if err==nil {
                    for _, spfip := range rawspfips {
                      iplist = append(iplist, spfip)
                    }
                  } else {
                    //log.Println(err.Error())
                    return iplist,err
                  }

                }
              }
            }
            //gather all IP4 adresses and add them to return array:
            if strings.HasPrefix(record, "ip4:") {
              target := strings.Split(record, "ip4:")
              if len(target[1]) != 0 {
                _, ipNet, err := net.ParseCIDR(target[1])
                if err == nil {
                  iplist = append(iplist, ipNet.String())
                } else {
                  ip := net.ParseIP(target[1])
                  if ip != nil {
                    if !CheckStringInArray(ip.String(), iplist) {
                      iplist = append(iplist, ip.String())
                    }
                  }
                }
              }
            }

            //gather all ip6 adresses and add them to return array:
            if strings.HasPrefix(record, "ip6:") {
              target := strings.Split(record, "ip6:")
              if len(target[1]) != 0 {
                _, ipNet, err := net.ParseCIDR(target[1])
                if err == nil {
                  iplist = append(iplist, ipNet.String())
                } else {
                  ip := net.ParseIP(target[1])
                  if ip != nil {
                    if !CheckStringInArray(ip.String(), iplist) {
                      iplist = append(iplist, ip.String())
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  //reset loop check before exit
  session.peer.LoopCheck=nil

  return
}

//Function to check if source "from" DOMAIN permits IP to connect to external SMTP server on belhalf of that DOMAIN. DOMAIN is taken from source (FROM) email address: eg USER @ DOMAIN, We assume that we permit A, MX and SPF dns records. 
func (session *session) CheckIPIsAllowed(ip, domain string) (valid bool, err error) {
  defer recovery()

  log.Println("IP: " + ip )
  log.Println("From: " + domain)
  valid = false

  //gather all ips in one iplist array
  aiplist, err := LookupValidAIPs(domain)
  if err != nil {
    return
  }
  mxiplist, err := LookupValidMXIPs(domain)
  if err != nil {
    return 
  }
  spfiplist, err := session.LookupValidSPFIPs(domain)
  if err != nil {
    log.Println(err.Error())
    return 
  }
  var iplist []string
  //append uniq a ips
  if aiplist!=nil {
    for _, aip := range aiplist {
      if !CheckStringInArray(aip, iplist) {
        iplist = append(iplist, aip)
      }
    }
  }
  //append uniq mx ips
  if mxiplist!=nil {
    for _, mxip := range mxiplist {
      if !CheckStringInArray(mxip, iplist) {
        iplist = append(iplist, mxip)
      }
    }
  }
  //append uniq spf ips
  if spfiplist!=nil {
    for _, spfip := range spfiplist {
      if !CheckStringInArray(spfip, iplist) {
        iplist = append(iplist, spfip)
      }
    }
  }

  //log all ips
  //if iplist!=nil {
  //  for _, allip := range iplist {
  //    log.Println("CURRENT IPLIST:" + allip)
  //  }
  //}
  if iplist==nil {
    err=errors.New("Lookup of A, MX, SPF records for domain " + domain + " failed.")
    valid = false
    log.Println(err.Error())
  } else {
    //process sender ip
    for _, target := range iplist {
      _, ipNet, err := net.ParseCIDR(target)
      if err == nil {
        if ipNet.Contains(net.ParseIP(ip)) {
          valid = true
          //log.Println(ipNet, " contain " + ip)
          //} else {
          //log.Println(ipNet, " do not contain " + ip)
        }
      } else {
        ipADDR := net.ParseIP(target)
        if ipADDR.Equal(net.ParseIP(ip)) {
          valid = true
          //log.Println(ipADDR, " contain " + ip)
          //} else { 
          //log.Println(ipADDR, " do not contain " + ip)
        }
      }
    }
  }
  return 
}

//Function to check if destination "to" DOMAIN is served (permited/relayed) on local SMTP server.
func (session *session) CheckRelayIsAllowed (domain string) (valid bool, err error) {
  defer recovery()

  log.Println("To: " + domain)
  valid = false

  //gather all ips in one iplist array
  mxiplist, err := LookupValidMXIPs(domain)
  if err != nil {
    return 
  }
  spfiplist, err := session.LookupValidSPFIPs(domain)
  if err != nil {
    return
  }


  var iplist []string
  //append a ips
  //if aiplist!=nil {
  //  for _, aip := range aiplist {
  //    if !CheckStringInArray(aip, iplist) {
  //      iplist = append(iplist, aip)
  //    }
  //  }
  //}
  //append mx ips
  if mxiplist!=nil {
    for _, mxip := range mxiplist {
      if !CheckStringInArray(mxip, iplist) {
        iplist = append(iplist, mxip)
      }
    }
  }
  //append spf ips
  if spfiplist!=nil {
    for _, spfip := range spfiplist {
      if !CheckStringInArray(spfip, iplist) {
        iplist = append(iplist, spfip)
      }
    }
  }
  ////log all ips
  //if iplist!=nil {
  //  for _, allip := range iplist {
  //  log.Println(allip)
  //  }
  //}

  if iplist==nil {
    err=errors.New("Lookup of MX and SPF records for domain " + domain + " failed.")
    valid = false
    log.Println(err.Error())
  } else {
    ifaces, _ := net.Interfaces()
    // handle err
    for _, i := range ifaces {
      addrs, _ := i.Addrs()
      // handle err
      for _, addr := range addrs {
        var ip net.IP
        switch v := addr.(type) {
        case *net.IPNet:
          ip = v.IP
        case *net.IPAddr:
          ip = v.IP
        }

        // process destination ip
        for _, target := range iplist {
          _, ipNet, err := net.ParseCIDR(target)
          if err == nil {
            if ipNet.Contains(net.ParseIP(ip.String())) {
              valid = true
            }
          } else {
            ipADDR := net.ParseIP(target)
            if ipADDR.Equal(net.ParseIP(ip.String())) {
              valid = true
            }
          }
        }
      }    
    }
  }
  return 
}

//***Spf section end***


//***Mailbox section start***
//mailbox section: implements various smtpd mailbox related security checks like login/password and others. 

//Function to verify on remote smtp server login and password used for local mailbox - it connects to remote SMTP server and verify provided AUTH LOGIN credentials.
func VerifyUserPassOnRemoteSmtpd(user,pass,domain string) (valid bool) {
  valid = false

  mxiplist, err := LookupValidMXIPs(domain)
  if err != nil {
    return
  }


  for _, host := range mxiplist {

    tlsconfig := &tls.Config{
      InsecureSkipVerify:   true,
      ServerName:           host,
    }

    conn, err := tls.Dial("tcp", host, tlsconfig)
    if err != nil {
      log.Println("Error: SMTP connect (tls.Dial)", err)
    }

    client, err := smtp.NewClient(conn, host)
    if err != nil {
      log.Println("Error: Unable to connect to SMTP serverc", err)
    }

    auth := smtp.PlainAuth("", user, pass, host)

    err = client.Auth(auth); 
    if err == nil {
      valid = true
    }
  }
  return

}

