#!/bin/bash

if [ ! -d /tmp/healthCheck ]; then
  mkdir -p /tmp/healthCheck 
fi

logCheckDays=7
currentDay=$(date +%F)
sinceLogDay=$(date +%F -d "$logCheckDays days ago")
healthLogDir="/tmp/healthCheck";cd /tmp/healthCheck
#错误文件大小阈值，20480B=20K
maxLogSize=20480
Domain=("www.sf-express.com")
k8sConfDir="/etc/kubernetes"
#软中断百分比阈值
maxcpuSI=80
#contrack使用百分比阈值
maxusedConntrackPercentage=80
#文件描述符百分比阈值
maxfilePercentage=80
#dockers进程描述符百分比阈值
maxdockerFDUsedPercentage=80
#磁盘使用率百分比阈值
maxDUpercentage=85
#网卡PPS阈值
maxNicPPS=300000
#网卡带宽阈值，以万兆卡计算
maxNicTraffic=1000000
#线程数使用率阈值
maxPidUsagePercentage=80
#僵尸进程个数阈值
maxZProcessNum=10
#磁盘IO队列长度阈值
maxIOAvgquSize=5
#磁盘读写wait值阈值，ms
maxIOAwait=100
#时间差阈值,单位秒(s)
maxTimeDiff=1


#定义日志的最大字节数，20480B=20K
checkLogSize(){
  du -b $1 |awk -v size=$maxLogSize '{if($1>size){print "false"}else{print "true"}}'
}

blue(){
    echo -e "\033[34m $1 \033[0m"
}

green(){
    echo -e "\033[32m $1 \033[0m"
}

bred(){
    echo -e "\033[31m\033[01m\033[05m $1 \033[0m"
}

byellow(){
    echo -e "\033[33m\033[01m\033[05m $1 \033[0m"
}

red(){
    echo -e "\033[31m\033[01m $1 \033[0m"
}

yellow(){
    echo -e "\033[33m\033[01m $1 \033[0m"
}

common_dns_check(){
  if ! host "$1" >/dev/null;then
    red "  └──[ERROR] node check domain $domain error"
  else
    green "  └──[INFO] node check domain $domain pass"
  fi
}

check_node_dns() {
  for domain in "${Domain[@]}";do
    common_dns_check "$domain"
  done
}

check_node_to_apiserver(){
  local apiserver=$(grep server "$k8sConfDir"/kubelet.conf|awk -F server: '{print $2}'|sed -e 's/^[[:space:]]*//')
  local serverStatus=$(curl -sk "$apiserver"/healthz)
  if [[ "$serverStatus" == "ok" ]];then
    green  "  └──[Info] node -> apiserver  is ok"
  else
    red  "  └──[Error] node -> apiserver is $serverStatus"
  fi
}

	#检查系统负载
check_cpuload(){
cpuCount=$(lscpu |grep 'CPU(s):'|grep -v -i numa|awk '{print $NF}')
maxCpuLoad=$(($cpuCount*2))
loadAverage=$(uptime |awk -F ':' '{print  $NF}')
result=$(echo $loadAverage|awk  -v load=$maxCpuLoad '{if($1<load && $2<load && $3<load){print "OK"}else{print "highLoad"}}')
if [[ $result == "OK" ]]; then
  echo -e "[INFO]SYSTEMLOAD_the system load average is health,the value is: $loadAverage\n"
else
  echo -e "[ERROR]SYSTEMLOAD_the system load average is too high,value is:$loadAverage\n"
fi
}
    #检查CPU软中断
check_cpuSI(){
mpstat -P ALL 1 30  1>$healthLogDir/mpstat-$currentDay.log
mpResult=$(cat $healthLogDir/mpstat-$currentDay.log |grep -v -E "^$|%soft|_x86_64" |awk -v si=$maxcpuSI '$(NF-4)>si {print}')
if [[ -z $mpResult ]];then
  echo -e "[INFO]CPUSI_the node cpu softinterrupt is OK\n"
else
  echo -e "[ERROR]CPUSI_the node cpu softinterrupt is HIGH:\n$mpResult"
fi
}

	#输出节点CPU request使用率
  
	#输出节点内存 request使用率
  
	#输出磁盘使用率
check_diskUsage(){
duResult=$(df -ht xfs|grep -v Filesystem|awk -v usage=$maxDUpercentage '{gsub("%", "", $5)}$(NF-1)>usage { print $0}')
if [[ -z $duResult ]];then
  echo -e "[INFO]DISKUSAGE_the node diskUsage is OK\n"
else
  echo -e "[ERROR]DISKUSAGE_the node diskUsage is HIGH:\n$duResult\n"
fi
}
	
	#输出磁盘IO情况
check_diskIO(){
DISKS=$(ls /dev/sd[a-z] /dev/vd[a-z]  2>/dev/null)
for d in $DISKS
  do
	export logFileName=$(echo "`echo $d|awk -F'/' '{print $NF}'`-`date +%F`")
    iostat -x -d $d 1 30  1>/tmp/healthCheck/$logFileName.log
	cd /tmp/healthCheck
	#maxReadIOPS=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $4}'  |grep -v -E '^$|r\/s'|sort  -nr|head -n1 )
	#avgReadIOPS=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $4}'|grep -v -E '^$|r\/s'|awk '{sum+=$1} END {print sum/NR}')
	#maxWriteIOPS=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $5}'  |grep -v -E '^$|w\/s'|sort  -nr|head -n1 )
	#avgWriteIOPS=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $5}'|grep -v -E '^$|w\/s'|awk '{sum+=$1} END {print sum/NR}')
	#maxReadKB=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $6}'  |grep -v -E '^$|rkB\/s'|sort  -nr|head -n1 )
	#avgReadKB=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $6}'  |grep -v -E '^$|rkB\/s'|awk '{sum+=$1} END {print sum/NR}')
	#maxWriteKB=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $7}'  |grep -v -E '^$|wkB\/s'|sort  -nr|head -n1 )
	#avgWriteKB=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $7}'  |grep -v -E '^$|wkB\/s'|awk '{sum+=$1} END {print sum/NR}')
	#maxAvgqu_sz=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $9}'  |grep -v -E '^$|avgqu-sz'|sort  -nr|head -n1 )
	#avgAvgqu_sz=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $9}'  |grep -v -E '^$|avgqu-sz'|awk '{sum+=$1} END {print sum/NR}')
	#maxAwait=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $10}'  |grep -v -E '^$|await'|sort  -nr|head -n1 )
	#avgAwait=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $10}'  |grep -v -E '^$|await'|awk '{sum+=$1} END {print sum/NR}')
	#maxR_await=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $11}'|grep -v -E '^$|r_await'|sort  -nr|head -n1 )
	#avgR_await=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $11}'|grep -v -E '^$|r_await'|awk '{sum+=$1} END {print sum/NR}')
	#maxW_await=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $12}'|grep -v -E '^$|w_await'|sort  -nr|head -n1 )
	#avgW_await=$(cat $logFileName.log|grep -v "_x86_64_" |awk '{print $12}'|grep -v -E '^$|w_await'|awk '{sum+=$1} END {print sum/NR}')
	IOResult=$(cat $logFileName.log|grep -v -E '^$|Device:|_x86_64_'|awk  -v avgqu=$maxIOAvgquSize -v iowait=$maxIOAwait '$9>avgqu||$10>iowait||$11>iowait||$12>iowait {print}')
	if [[ -z $IOResult ]];then
	  echo -e "[INFO]DISKIO_the disk:$d IO status is OK\n"
	else
	  echo -e "[ERROR]DISKIO_the disk:$d IO status is HIGH:\n$IOResult\n"
	fi
	
	#echo -e "[INFO] disk $d:\nmaxReadIOPS:$maxReadIOPS\navgReadIOPS:$avgReadIOPS\nmaxWriteIOPS:$maxWriteIOPS\navgWriteIOPS:$avgWriteIOPS\nmaxReadKB:$maxReadKB\navgReadKB:$avgReadKB\nmaxWriteKB:$maxWriteKB\navgWriteKB:$avgWriteKB\nmaxAvgqu_sz:$maxAvgqu_sz\navgAvgqu_sz:$avgAvgqu_sz\nmaxAwait:$maxAwait\n"
  done
}


	#输出网卡情况,网卡不是eth开头时修改正则匹配
check_nic(){
NETDEV=$(ifconfig  -a |grep  -E  -o "^eth[0-9]*|^bond[0-9]*|^ens[0-9]*")
sar -n DEV 1  30 1>$healthLogDir/netStatus-$currentDay.log
for n in $NETDEV
  do
    cd /tmp/healthCheck
    #nicStatus=$(ip link show $n|grep  -o -E "state[[:space:]]*[[:upper:]]*"|awk '{print $NF}')
	#maxRxpckPercent=$(cat netStatus.log |grep $n|grep -v -E "veth*|Average:"|awk -v nic=$n '$(NF-7)==nic {print $(NF-6)}'|sort  -nr |head -n1)
	#maxTxpckPercent=$(cat netStatus.log |grep $n|grep -v -E "veth*|Average:"|awk -v nic=$n '$(NF-7)==nic {print $(NF-5)}'|sort  -nr |head -n1)
	#maxRxkBPercent=$(cat netStatus.log |grep $n|grep -v -E "veth*|Average:"|awk -v nic=$n '$(NF-7)==nic {print $(NF-4)}'|sort  -nr |head -n1)
	#maxTxkBPercent=$(cat netStatus.log |grep $n|grep -v -E "veth*|Average:"|awk -v nic=$n '$(NF-7)==nic {print $(NF-3)}'|sort  -nr |head -n1)
	#avgRxpckPercent=$(cat netStatus.log |grep $n|grep -v -E "veth*"|grep Average|awk -v nic=$n '$(NF-7)==nic {print $(NF-6)}')
	#avgTxpckPercent=$(cat netStatus.log |grep $n|grep -v -E "veth*"|grep Average|awk -v nic=$n '$(NF-7)==nic {print $(NF-5)}')
	#avgRxkBPercent=$(cat netStatus.log |grep $n|grep -v -E "veth*"|grep Average|awk -v nic=$n '$(NF-7)==nic {print $(NF-4)}')
	#avgTxkBPercent=$(cat netStatus.log |grep $n|grep -v -E "veth*"|grep Average|awk -v nic=$n '$(NF-7)==nic {print $(NF-3)}')
	nicResult=$(cat netStatus-$currentDay.log |grep $n|grep -v -E "veth*"|grep Average|awk -v nic=$n -v pps=$maxNicPPS -v traffic=$maxNicTraffic  '$(NF-7)==nic &&($(NF-6)>pps || $(NF-5)>pps ||$(NF-4)>traffic ||$(NF-3)>traffic) {print }')
	if [[ -z $nicResult ]];then
	  echo -e "[INFO]NET_the nic:$n traffic status is OK\n"
	else
	  echo -e "[ERROR]NET_the nic:$n traffic status is HIGH:\n$nicResult\n"
	fi
	
	#echo -e "[INFO]NETDEV $n---\nStatus:$nicStatus\nmaxRxpckPercent:$maxRxpckPercent\nmaxTxpckPercent:$maxTxpckPercent\nmaxRxkBPercent:$maxRxkBPercent\nmaxTxkBPercent:$maxTxkBPercent\n"average is" $avgRxpckPercent $avgTxpckPercent $avgRxkBPercent $avgTxkBPercent\n---\n"
  done
}

	# 输出docker状态检查
	
	## docker服务状态
check_docker(){
dockerdIsActived=$(systemctl  is-active docker)
if  [[ $dockerdIsActived == "active" ]]; then
   echo "[INFO]DOCKER__the dockerd process status is active"
  else 
   echo "[ERROR]DOCKER__the dockerd process is not running"
fi
  
	## docker ps 没有hang住
dockerPsTMout=5s
timeout  $dockerPsTMout docker ps  1>/dev/null 2>&1
if [[ $? -eq 0 ]];then
   echo "[INFO]DOCKER__dockerd has hanged check passed"
else
   echo "[ERROR]DOCKER__dockerd hang happend"
fi
  

  
  ## docker 描述符
dockerPid=$(ps aux |grep /bin/dockerd|grep -v grep |awk '{print $2}')
if [[ ! -z $dockerPid ]] ;then
  dockerOpenfileLimit=$(cat /proc/$dockerPid/limits |grep files |awk '{print $(NF-1)}')
  usedFD=$(ls -lR  /proc/$dockerPid/fd |grep "^l"|wc -l)
  dockerFDUsedPercentage=$(awk 'BEGIN{printf "%.3f%%\n",('$usedFD'/'$dockerOpenfileLimit')*100}')
  if [[ $(echo $dockerFDUsedPercentage|awk '{gsub("%", "", $1)} {print }') > $maxdockerFDUsedPercentage ]];then
    echo -e "[ERROR]DOCKER_docker FD has used more than $maxdockerFDUsedPercentage%,the used info is:\nmax:$dockerOpenfileLimit\nusedFD:$usedFD\ndockerFDUsedPercentage:$dockerFDUsedPercentage\n"
  else
    echo -e "[INFO]DOCKER_dockerd FD used is OK, openfileLimit info:\nmax:$dockerOpenfileLimit\nusedFD:$usedFD\ndockerFDUsedPercentage:$dockerFDUsedPercentage\n"
  fi 
fi 
  

  ## 检查docker和containerd容器状态是否一致
Upcontainers=$(docker ps |grep Up|awk '{print $1}')
if which ctr &>/dev/null;then
 ctr --namespace moby --address /var/run/docker/containerd/containerd.sock  task  list 1>containerdTasks.list
  if [[ $? -eq 0 ]];then
	for i in $Upcontainers
	  do
		 cat containerdTasks.list|grep $i |grep -q  RUNNING
		 if [[ $? -ne 0 ]];then
		   echo "[ERROR]DOCKER_the abnormal container ID is: $i"
		 fi
	  done
  fi
fi	  
  
  ## 检查7天内dockers日志是否有error信息
journalctl -x  --since $sinceLogDay   -u docker  1>docker-$currentDay.log
grep -E -i "err|ERR|error|Error" docker-$currentDay.log 1>docker-$currentDay-Error.log
if [[ $(checkLogSize docker-$currentDay-Error.log) == "true" ]];then
	if [[  -s  docker-$currentDay-Error.log ]]; then
	  echo  -e "[ERROR]DOCKER__docker error logs is: $(cat docker-$currentDay-Error.log)\n\n"
	else
		echo  -e "[INFO]DOCKER__docker has no error logs\n\n"
	fi
else
    echo -e "[ERROR]DOCKER__docker error logs is too large,log file in $healthLogDir/docker-$currentDay-Error.log"
fi


###检查UP状态容器进程是否存在
for c in $Upcontainers
 do
  cPID=$(docker inspect --format "{{.State.Pid}}" $c)
  ls /proc/$cPID -ld 1>/dev/null 2>&1
  if [[ $? -ne 0 ]];then
    echo "[ERROR]DOCKER_the containerID:$c process is not exist"
  fi
 done
}

check_containerd() {
  if ! pgrep -fl containerd|grep -Ev "shim|dockerd" > /dev/null ;then
    red "  [ERROR]CONTAINERD_service containerd is not running,process is not exist"
  else
    green "[INFO]CONTAINERD_check containerd process is OK"
  fi
}

  # 输出kubelet检查结果
  ## kubelet进程状态
check_kubelet(){
kubeletIsActived=$(systemctl  is-active kubelet)
if  [[ $kubeletIsActived == "active" ]]; then
   echo -e "[INFO]KUBELET_the kubelet processs  status is active\n"
else 
   echo  -e "[ERROR]KUBELET_the kubelet  process is not running\n"
fi
  
  ## kubelet健康端口检查
kubeletCheckEndpoint=$(ss -tunlp|grep kubelet|grep 127.0.0.1|grep 102|awk '{print $5}')  
kubeletCheckResult=$(curl $kubeletCheckEndpoint/healthz)
if [[ $kubeletCheckResult == "ok" ]] ;then
  echo -e "[INFO]KUBELET_kubelet port health check passed\n"
else
  echo  -e "[ERROR]KUBELET_kubelet port health check not paased\n"
fi
  
  ## kubelet7天内日志
journalctl -x   --since $sinceLogDay   -u kubelet 1>kubelet-$currentDay.log 
grep -E  "E[0-9]+|err|ERR|error|Error" kubelet-$currentDay.log 1>kubelet-$currentDay-Error.log
if [[ $(checkLogSize kubelet-$currentDay-Error.log) == "true" ]];then
	if [[  -s  kubelet-$currentDay-Error.log ]]; then
	  echo  -e "[ERROR]KUBELET_kubelet error logs is: $(cat kubelet-$currentDay-Error.log)\n\n"
	else
		echo  -e "[INFO]KUBELET_kubelet has no error logs\n\n"
	fi
else
    echo -e "[ERROR]KUBELET_kubelet error logs is too large,log file in $healthLogDir/kubelet-$currentDay-Error.log"
fi
}
  # 输出kube-proxy检查结果
check_kube_proxy(){
  ## kube-proxy 健康端口检查
kubeProxyCheckResult=$(curl 127.0.0.1:10249/healthz)
if [[ $kubeProxyCheckResult == "ok" ]] ;then
  echo "[INFO]KUBE-PROXY_kube-proxy port health check passed"
else
  echo "[ERROR]KUBE-PROXY_kube-proxy port health check not paased"
fi 
  
  ## kube-proxy错误日志过滤 
proxyContainerID=$(docker ps |grep kube-proxy|grep -v pause|awk '{print $1}')
if [[ ! -z $proxyContainerID ]]; then
	docker logs $proxyContainerID  -t --since $sinceLogDay  --details >& kube-proxy-$currentDay.log
	grep -E  "E[0-9]+|err|ERR|error|Error" kube-proxy-$currentDay.log 1>kube-proxy-$currentDay-Error.log
	if [[ $(checkLogSize kube-proxy-$currentDay-Error.log) == "true" ]];then
	  if [[  -s  kube-proxy-$currentDay-Error.log ]]; then
	    echo  -e "[ERROR]KUBE-PROXY_kube-proxy error logs is: $(cat kube-proxy-$currentDay-Error.log)\n\n"
	  else
		echo  -e "[INFO]KUBE-PROXY_kube-proxy has no error logs\n\n"
	  fi
   else
     echo -e "[ERROR]KUBE-PROXY_kube-proxy error logs is too large,log file in $healthLogDir/kube-proxy-$currentDay-Error.log"
   fi
else
    echo -e "[ERROR]KUBE-PROXY_no found kube-proxy containerd this node"
fi
} 

 #检查最大文件打开数
check_openfiles(){
openfileUsed=$(cat /proc/sys/fs/file-nr|awk '{print $1}')
maxOpenfiles=$(cat /proc/sys/fs/file-nr|awk '{print $NF}')
filePercentage=$(awk 'BEGIN{printf "%.3f%%\n",('$openfileUsed'/'$maxOpenfiles')*100}')
if [[ $(echo $filePercentage|awk '{gsub("%", "", $1)} {print }') > $maxfilePercentage ]];then
  echo -e "[ERROR]OPENFILE_this node FD has used more than $maxfilePercentage%,the used info is:\nopenfileUsed:$openfileUsed\nmaxOpenfiles:$maxOpenfiles\nopenfileUsedPercentage:$filePercentage\n"
else
  echo -e "[INFO]OPENFILE_this node FD used is OK, openfile info:\nopenfileUsed:$openfileUsed\nmaxOpenfiles:$maxOpenfiles\nopenfileUsedPercentage:$filePercentage\n"
fi 
}


  #conntrack使用率
check_nf_conntrack(){
conntrackMax=$(cat /proc/sys/net/nf_conntrack_max) 
usedConntrack=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
usedConntrackPercentage=$(awk 'BEGIN{printf "%.3f%%\n",('$usedConntrack'/'$conntrackMax')*100}')
if [[ $(echo $usedConntrackPercentage|awk '{gsub("%", "", $1)} {print }') > $maxusedConntrackPercentage ]];then
  echo -e "[ERROR]NF_CONNTRACK_this node nf-conntrack has used more than $maxusedConntrackPercentage%,the used info is:\nconntrackMax:$conntrackMax\nusedConntrack:$usedConntrack\nPercentage:$usedConntrackPercentage\n"
else
  echo -e "[INFO]NF_CONNTRACK_this node nf-conntrack has used is OK, nf-contrack  info:\nconntrackMax:$conntrackMax\nusedConntrack:$usedConntrack\nPercentage:$usedConntrackPercentage\n"
fi 
}
  
check_pid(){
usedPidNUM=$(ls -ld  /proc/[0-9]* |wc -l)
pidMax=$(cat /proc/sys/kernel/pid_max)
pidUsedPercentage=$(awk 'BEGIN{printf "%.3f%%\n",('$usedPidNUM'/'$pidMax')*100}')
if [[ $(echo $pidUsedPercentage|awk '{gsub("%", "", $1)} {print }') > $maxPidUsagePercentage ]];then
  echo -e "[ERROR]PID_NUM_this node pid number  has used more than $maxPidUsagePercentage%,the used info is:\nusedPidNum:$usedPidNUM\npidMax:$pidMax\nPercentage:$pidUsedPercentage\n"
else
  echo -e "[INFO]PID_NUM_this node pid number has used is OK, pid  used info:\nusedPidNum:$usedPidNUM\npidMax:$pidMax\nPercentage:$pidUsedPercentage\n"
fi 
}
  
  #Z进程检查
check_z_process(){
ZNUM=$(top -n 1|grep Tasks|awk  -F',' '{print $NF}'|awk '{print $(NF-1)}' )
if [[ $ZNUM == 0 ]];then
  echo -e  "[INFO]Z_PROCESS-no found zombie process\n\n"
elif [[ $ZNUM -gt $maxZProcessNum ]];then
  ZTasks=$(ps -ef | grep defunct | grep -v grep)
  echo -e "[ERROR]Z_PROCESS-more than $maxZProcessNum zombie process found,the tasks is: $ZTasks\n"
else
  echo -e "[ERROR]Z_PROCESS-has found Z process,but less than $maxZProcessNum\n"
fi
}
  #时间差检查
check_ntp(){  
timeDiff=$(chronyc  sources|grep -E "^\^\*" |awk '{print $(NF-3)}'|cut  -d[ -f 1)
timeNUM=$(echo $timeDiff|grep -E -o "[0-9]*")
timeUnit=$(echo $timeDiff|grep -E -o "[a-z]*")
if [[ $timeUnit == "ns" ]];then
  timeDiffNum=$(awk 'BEGIN{printf "%0.10f",'$timeNUM'/1000000000}')
elif [[ $timeUnit == "us" ]];then
  timeDiffNum=$(awk 'BEGIN{printf "%0.10f",'$timeNUM'/1000000}')
elif [[ $timeUnit == "ms" ]];then
  timeDiffNum=$(awk 'BEGIN{printf "%0.10f",'$timeNUM'/1000}')
else
  timeDiffNum=$timeNUM
fi  

if [[ $(echo "$timeDiffNum" > "$maxTimeDiff"|bc) -eq 1  ]];then
 echo -e "[ERROR]NTP_TIME:this node Time deviation is more than $maxTimeDiff s"
else 
 echo -e "[INFO]NTP_TIME: this node Time Synchronize to source is OK"
fi
}

 #message日志检查
check_msg_logs(){
grep -E "Container kill faild |\
Container kill faild.count |\
Trying direct SIGKILL |\
Container kill faild because of 'container not found' or 'no sudh process' |\
OOM KILL |\
Abort command issued |\
NIC link is down |\
Path is down |\
OFFILE unexpectedly |\
Call Trace |\
Not respoding |\
Write error |\
IO failure |\
Filesystem read-only |\
Failing path |\
No liveness for |\
xfs_log_force:error |\
I/O error |\
EXT4-fs error |\
Uncorrected hardware memory error |\
Device offlined |\
Unrecoverable medium error during recovery on PD |\
tx_timeout |\
Container runtime is down PLEG is not healthy |\
_Call_Trace"  /var/log/messages 1>message-$currentDay-Error.log

if [[ $(checkLogSize message-$currentDay-Error.log) == "true" ]];then
  if [[  -s  message-$currentDay-Error.log ]]; then
	echo  -e "[ERROR]MESSAGE_message error logs is: $(cat message-$currentDay-Error.log)\n\n"
  else
	echo  -e "[INFO]MESSAGE_message has no error logs\n\n"
  fi
else
 echo -e "[ERROR]MESSAGE_message error logs is too large,log file in $healthLogDir/message-$currentDay-Error.log"
fi
}


check_weaver_node(){
 curl  127.0.0.1:6784/status  1>weaver-status-$currentDay.txt
 curl  127.0.0.1:6784/status/connections 1>weaver-connections-$currentDay.txt
 curl  127.0.0.1:6784/ip |jq .  1>weaver-ip-$currentDay.txt
 weaverStatus=$(cat weaver-status-$currentDay.txt |grep  Status|awk -F":| " '{print $NF}')
 if [[ $weaverStatus == "ready" ]]; then
   echo  -e "[INFO]WEAVER_weaver is ready in this node\n\n"
 else
   echo -e "[ERROR]WEAVER_weaver is  not ready in this node\n\n"
 fi
 
 weaverEstablishNum=$(cat weaver-connections-$currentDay.txt |grep -v self|grep  established |wc -l)
 weaverFastdpNum=$(cat weaver-connections-$currentDay.txt |grep -v self|grep fastdp|wc -l)
 if [[ $weaverEstablishNum == $weaverFastdpNum ]];then
   echo -e "[INFO]WEAVER_the weaver connection check passed\n\n"
 else 
   wrongConnection=$(cat weaver-connections-$currentDay.txt |grep  establish|grep -v fastdp)
   echo -e "[ERROR]WEAVER_found wrong connections:\n$wrongConnection\n\n"
 fi
 
 cat weaver-ip-$currentDay.txt |jq '.owned[]|{id:.containerid,addr:.addrs[0]}'|grep -E -v ^$|grep -v -E  '{|}'|xargs  -n4 1>weaver-ip-$currentDay-modify.txt
 
 weaverBadIP=$(cat weaver-ip-$currentDay-modify.txt|awk -F',|:' '{print $2}'|grep -E '(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])')
 
 if [[ ! -z $weaverBadIP ]]; then
   echo -e "[ERROR]WEAVER_found weaver disclose IP is:\n$weaverBadIP\n\n"
 else
   echo -e "[INFO]WEAVER_no found weaver disclose IP"
 fi
}

check_node_dns
check_cpuload
check_cpuSI
check_diskUsage
check_diskIO
check_nic
check_docker
check_containerd
check_kubelet
check_kube_proxy
check_openfiles
check_nf_conntrack
check_pid
check_z_process
check_ntp
check_msg_logs
check_weaver_node
