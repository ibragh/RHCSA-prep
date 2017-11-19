#!/bin/bash

function setupExam {
  QESTIONSFOLDER=/mytmp
  ANSWERSFOLDER=/exam/answers
  garbage=/dev/null
  SHARESFOLDER=/exam/shares
  #export QESTIONSFOLDER; export $ANSWERSFOLDER; export garbage
  mkdir $QESTIONSFOLDER 2> $garbage
  mkdir -p $QESTIONSFOLDER/err 2> $garbage

  for errfiles in {1..20}; do
    rm -f $QESTIONSFOLDER/err/q$errfiles 2> $garbage
    touch $QESTIONSFOLDER/err/q$errfiles
  done
  rm -f $QESTIONSFOLDER/words.txt 2> $garbage
  for word in boot book booze machine boots bungie bark aardvark broken\$tuff robots; do
    echo "$word" >> $QESTIONSFOLDER/words.txt
  done
}

function Pass_Fail {
  if [ "$1" == "" ]; then
    ANS="Q$2 .. PASS"
    echo "$ANS"
  else
    ANS="Q$2 .. FAIL"
    echo -e "$ANS"
    echo -e "$1"
  fi
}

#Q1
function q1 {
  #----- setup part
  rm -f $QESTIONSFOLDER/headtail.txt 2> $garbage
  for letter in {a..z}; do
    echo "$letter" >> $QESTIONSFOLDER/headtail.txt
  done
  head -n 11  $QESTIONSFOLDER/headtail.txt >  $QESTIONSFOLDER/diff.txt
  tail -n 6  $QESTIONSFOLDER/headtail.txt >>  $QESTIONSFOLDER/diff.txt

  #----- test part
  # !!!!!!!!!! ADD if ls directory
  QDIFF=$(diff $QESTIONSFOLDER/diff.txt $ANSWERSFOLDER/headtail.txt 2> $QESTIONSFOLDER/err/q1 |wc -l)
  QERR=$(cat $QESTIONSFOLDER/err/q1 |wc -l)
  if [ "$QERR" -gt "0" ]; then
    FOLDERS_ERR+="File $ANSWERSFOLDER/headtail.txt not found. make sure you typed file name correctly"
  elif [ "$QDIFF" -gt "0" ];then
    FOLDERS_ERR+="Content is not correct. It should be head 11 and tail 6 "
  fi

  Pass_Fail "$FOLDERS_ERR" "1"
}
#Q2
function q2 {
  #-------------setup
  #remove users if they exist.... by my script
  #------------ test

  for username in ahmed sami khaled mohammed; do
    grepuser=$(cut -d : -f1 /etc/passwd | grep -c "^$username$")
    if [ "$grepuser" -eq "0" ]; then
      user_ERR+="USER $username is not added. make sure you typed the correct name\n"
      # + becuse there is more than one user check
    fi

  done

  Pass_Fail "$user_ERR" "2"
}
# Q#
function q3 {
  #-------------setup
  #remove users if they exist.... by my script
  #------------ test

  # check groups first
  for groupname in sales hr company; do
    checkgroups=$(cut -d : -f 1 /etc/group | grep -c "^$groupname$" )
    if [ "$checkgroups" -eq "0" ]; then
      Groups_ERR+="group $groupname does not exist \n"
    fi
  done
# groups needs to be done better....
  for username in sami khaled; do
    grepcompany=$(id "$username" 2> $garbage | grep -c "company")
    grephr=$(id "$username"  2> $garbage | grep -c "hr")
    if [ "$grephr" -eq "0" ] || [ "$grepcompany" -eq "0" ]; then
      Groups_ERR+="Group hr or company is not added to $username \n"
    fi
  done

  for username in ahmed mohammed; do
    grepcompany=$(id "$username"  2> $garbage | grep -c "company" )
    grephr=$(id "$username" 2> $garbage | grep -c "sales" )
    if [ "$grephr" -eq "0" ] || [ "$grepcompany" -eq "0" ]; then
      Groups_ERR+="Group sales or company is not added to $username \n"
    fi
  done

  Pass_Fail "$Groups_ERR" "3"

}

function q4 {

  # ---------------- setup

  # ---------- test
  ANS=""
  grepmaxpassword=$(grep "^PASS_MAX_DAYS" /etc/login.defs | grep -c "50")
  if [ "$grepmaxpassword" -eq "0" ]; then
    ANS="Q4 .. FAIL"
    password_ERR+="You did not set maximam days to change password for newly users \n"
  elif [ "$grepmaxpassword" -eq "1" ]; then
    ANS="Q4 .. PASS"
  else
    ANS="Something .. else"
  fi

  for username in ahmed sami khaled mohammed; do
    grepagin=$(chage -l "$username" 2> $garbage |grep -c "password must be change")

    if [ "$grepagin" -lt "3" ]; then
      ANS="Q4 ... FAIL"
      password_ERR+="You did not force USER $username to change password in first login\n"
    fi
  done

  Pass_Fail "$password_ERR" "4"
}

function q5 {
  # -- setup

  # -- test
  ANS=""
  files_ERR=""
  # check if folder shares exist

  if ls -d "$SHARESFOLDER" &> $garbage ; then
    for file in file1 file2 file3; do
      lsfile=$(ls -l "$SHARESFOLDER/$file" 2> $garbage |wc -l)
      if [ "$lsfile" -eq "0" ]; then
        files_ERR+="file  $SHARESFOLDER/$file does not exist \n"
      elif [ "$lsfile" -eq "1" ]; then
        lsfile=$(ls -l $SHARESFOLDER/$file 2> $garbage|cut -d " " -f4)
        if [ "$lsfile" != "company" ]; then
          files_ERR+="group company is not the group of file $SHARESFOLDER/$file /n"
        fi
      fi
    done
    # check GID & StickBit
    gidcheck=$(ls -ld $SHARESFOLDER/ | cut -d " " -f1 |cut -d "r" -f3|grep -c -i "s"
    )
    stickbitcheck=$(ls -ld $SHARESFOLDER/ | cut -d " " -f1 |cut -d "r" -f4|grep -c -i "t"
    )

    if [ "$gidcheck" -eq "0" ]; then
      files_ERR+="GID is not set for $SHARESFOLDER \n"
    fi
    if [ "$stickbitcheck" -eq "0" ] ; then
      files_ERR+="Sticky bit is not set for $SHARESFOLDER \n"
    fi
    # check group owner
    lssharesowner=$(ls -ld $SHARESFOLDER  |cut -d " " -f4)
    if [ "$lssharesowner" != "company" ]; then
      files_ERR+="group company is not the group of directory $SHARESFOLDER \n"
    fi
  else
    files_ERR="folder $SHARESFOLDER does not exist"
  fi
Pass_Fail "$files_ERR" "5"
}
function q6 {
  #proccess using much CPU
  # ------ setup
  #!!!!!! cat /dev/zero > /dev/null &

  #processes=$(pgrep cat)
  #for ps in $processes; do
  #echo $p
  #done
  check_processes=$(pgrep -c cat &> $garbage)
  echo $check_processes
  if [[ $check_processes -gt 0 ]]; then
    ps_ERR="Proccess cat is not killed "
  fi

  Pass_Fail "$ps_ERR" "6"
}
function q7 {
  # user remoteuser on desktop can login to server withoutpassword

  true
}
function q8 {
  # configure rsyslog
  # ----------- setup .. make sure rsyslog is enabled and started

  # ----------- grading
  #check_rsyslog=$(grep -r "^mail.crit .*/var/log/mail.crit$" /etc/rsyslog.* | wc -l)
  check_rsyslog=$(grep -r "^mail.crit.*/var/log/mail.crit$" /etc/rsyslog.* | wc -l)

  if [[ $check_rsyslog -eq 0 ]]; then
    rsyslog_ERR="mail.crit /var/log/mail.crit is not added to rsyslog configurations"
  else
    logger -p mail.crit "test1234"
    if ls /var/log/mail.crit &> $garbage; then
      #logger_test=$(grep -c "test1234")
      #if [[ $logger_test -eq 0 ]]; then
      #  rsyslog_ERR+= "\n somthing wrong "
      #fi
      true
    else
      rsyslog_ERR+="File /var/log/mail.crit is not there. You should restart the service after adding the conf"
    fi
  fi

  Pass_Fail "$rsyslog_ERR" "8"
}
function q9 {
  #Network configurations
  # nmcli connection show mycon | grep -e "ipv4.addresses"
  # -e "connection.autoconnect:"
  # -e "ipv4.dns:"
  # -e "connection.type"
# ---- setup

# ---- grade
if [[ $(nmcli connection show | grep -c mycon) -eq 1 ]]; then

  if [[ $(nmcli connection show mycon | grep "ipv4.addresses" |
  awk '{print $2}') = "200.0.0.100//8" ]]; then
    network_ERR="IP is not correct. it should be ---------/-\n"
  fi
  if [[ $(nmcli connection show mycon | grep "ipv4.dns:" |
  awk '{print $2}') = "8.8.8.8" ]]; then
    network_ERR+="DNS IP is not correct. it should be ---------/-\n"
  fi
  if [[ $(nmcli connection show mycon | grep "connection.autoconnect" |
  awk '{print $2}') = "yes" ]]; then
    network_ERR+="connection autoconnect is no. it should be yes\n"
  fi
  if [[ $(nmcli connection show mycon | grep "connection.type" |
  awk '{print $2}'| grep -c -i ethernet) -eq 0 ]]; then
    network_ERR+="connection type is not correct. it should be ethernet"
  fi

else
network_ERR="Either you did not add myconn connection or there is more than one."
fi

Pass_Fail "$network_ERR" "9"

}
function q10 {
  # check services.. installed and enabled
  if [[ $(yum info vsftpd 2> $garbage | grep -c "installed") -eq 0 ]]; then
    services_ERR="vsftpd package is not installed\n"
  fi
  if [[ $(systemctl is-enabled rsyslog.service 2> $garbage | grep -c enabled)  -eq 0 ]]; then
    services_ERR+="rsyslog service is not enabled\n"
  fi
  if [[ $(systemctl is-enabled firewalld.service 2> $garbage | grep -c disabled)  -eq 0 ]]; then
    services_ERR+="firewall service is not disabled\n"
  fi
  if [[ $(yum info httpd 2> $garbage | grep -c "installed") -eq 0 ]]; then
    services_ERR+="httpd package is not installed"
  else
    if [[ $(systemctl is-active httpd.service | grep -c active)  -eq 0 ]]; then
      services_ERR+="httpd service is not active/started\n"
    fi
    if [[ $(systemctl is-enabled httpd.service | grep -c enabled)  -eq 0 ]]; then
      services_ERR+="httpd service is not enabled"
    fi
  fi

Pass_Fail "$services_ERR" "10"

}
function q11 {
  # check tar file.. by size ?
  # ----- setup
  tarPATH=/exam/tar
  mkdir -p $tarPATH
  for num in {1..5}; do
    dd if=$garbage of=$tarPATH/dummy$num bs=1 count=0 seek=20M &> $garbage
  done
  # ---- grade
  if ls $ANSWERSFOLDER/mytar.tar &> $garbage; then
    checksize=$(stat $ANSWERSFOLDER/mytar.tar | grep Size|cut -d : -f2|cut -d " " -f2)
    if [[ $checksize -lt 95000000 ]] || [[ $checksize -gt 105000000 ]]; then
      tar_ERR="Size of tar file should be between 100M & 105M"
    fi
  else
    tar_ERR="tar file $ANSWERSFOLDER/mytar.tar does not exist"
  fi
  Pass_Fail "$tar_ERR" "11"
}


setupExam
for num in {1..11}; do
  q$num
done
# add score to each question... after writing questions
echo "Final score is: VALUE/100"
