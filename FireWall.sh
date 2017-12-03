#!/bin/bash
#
# Simple PareFeu 
#
# 
#
### BEGIN INIT INFO
# Provides: firewall.sh
# Required-Start: $syslog $network
# Required-Stop: $syslog $network
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: Start firewall daemon at boot time
# Description: Custom Firewall scrip.
### END INIT INFO
# Description: Fichier de parefeu pour un serveur web  
# Action à réaliser : 
# chmod a+x /etc/init.d/firewall.sh
# update-rc.d firewall.sh defaults 20
# service firewall start
### END INIT INFO

##########################################
#          Variables                     #
##########################################

# Adresse IP du serveur
IP_SRV=

# Ports du serveur accessibles depuis l'extérieur
TCP_SERVICES="22 443" #ports tcp en écoute sur le serveur
UDP_SERVICES="" #port udp en écoute sur le serveur

# Ports cibles d'une communication émise par le serveur
REMOTE_TCP_SERVICES="21 80 443 " # web browsing
REMOTE_UDP_SERVICES="53 123" # DNS

# Activation des logs les plus bavards (oui/non)
LOGS=non



##########################
# Zone IPV6
##########################

# Désactivation d'ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 
echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6
echo 1 > /proc/sys/net/ipv6/conf/lo/disable_ipv6

IPT6="/sbin/ip6tables"
# echo "Mise en place des règles du PareFeu IPV6"
$IPT6 -F
$IPT6 -X
$IPT6 -t mangle -F
$IPT6 -t mangle -X
 
# Interdiction de tout IPV6
$IPT6 -P INPUT DROP
$IPT6 -P OUTPUT DROP
$IPT6 -P FORWARD DROP
 
##########################
# Zone IPV4
##########################

PATH=/bin:/sbin:/usr/bin:/usr/sbin

#########################################
# Mise en oeuvre des règles du Pare feu 
#########################################

fw_start () {

# Stratégie par défaut
/sbin/iptables -P INPUT DROP
/sbin/iptables -P FORWARD DROP
/sbin/iptables -P OUTPUT DROP

# A réactivier pour autoriser uniquement la france

if [ $LOGS=oui ] ; then
# On journalise les retours et les connexions sur loopback (attention logs probablements volumineux)
/sbin/iptables -A INPUT -m state --state ESTABLISHED -j LOG  --log-ip-options --log-tcp-options --log-tcp-sequence --log-prefix " INPUT established "
/sbin/iptables -A OUTPUT -m state --state ESTABLISHED -j LOG  --log-ip-options --log-tcp-options --log-tcp-sequence --log-prefix " OUTPUT established "

/sbin/iptables -A INPUT -m state --state RELATED -j LOG  --log-ip-options --log-tcp-options --log-tcp-sequence --log-prefix " INPUT related "
/sbin/iptables -A OUTPUT -m state --state RELATED -j LOG  --log-ip-options --log-tcp-options --log-tcp-sequence --log-prefix " OUTPUT related "

/sbin/iptables -A INPUT -i lo -j LOG  --log-ip-options --log-tcp-options --log-tcp-sequence --log-prefix " INPUT loopback "
/sbin/iptables -A OUTPUT -o lo -j LOG  --log-ip-options --log-tcp-options --log-tcp-sequence --log-prefix " OUTPUT loopback "
fi

# On autorise les retours de toutes les connexions
/sbin/iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
/sbin/iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# ainsi que les connexions entrantes et sortantes sur loopback
/sbin/iptables -A INPUT -i lo -j ACCEPT 			# préciser les ports autorisés
/sbin/iptables -A OUTPUT -o lo -j ACCEPT 			# préciser les ports autorisés


 
# Ouverture des ports
if [ -n "$TCP_SERVICES" ] ; then
for PORT in $TCP_SERVICES; do
 /sbin/iptables -A INPUT -p tcp -m state --state NEW --sport 1024:65535 --dport ${PORT} -j LOG  --log-ip-options --log-tcp-options --log-tcp-sequence --log-prefix " Connexion TCP vers FW "
 /sbin/iptables -A INPUT -p tcp -m state --state NEW -d $IP_SRV --sport 1024:65535 --dport ${PORT} -j ACCEPT
done
fi

if [ -n "$UDP_SERVICES" ] ; then
for PORT in $UDP_SERVICES; do
 /sbin/iptables -A INPUT -p udp -m state --state NEW --sport 1024:65535 --dport ${PORT} -j LOG  --log-ip-options --log-tcp-options --log-tcp-sequence --log-prefix " Connexion UDP vers FW "
 /sbin/iptables -A INPUT -p udp -m state --state NEW -d $IP_SRV --sport 1024:65535 --dport ${PORT} -j ACCEPT
done
fi

# Ouverture des ports
if [ -n "$REMOTE_TCP_SERVICES" ] ; then
for PORT in $REMOTE_TCP_SERVICES; do
 /sbin/iptables -A OUTPUT -p tcp -m state --state NEW --sport 1024:65535 --dport ${PORT} -j LOG  --log-ip-options --log-tcp-options --log-tcp-sequence --log-prefix " Connexion TCP sortant du FW "
 /sbin/iptables -A OUTPUT -p tcp -m state --state NEW -s $IP_SRV --sport 1024:65535 --dport ${PORT} -j ACCEPT
done
fi



if [ -n "$REMOTE_UDP_SERVICES" ] ; then
for PORT in $REMOTE_UDP_SERVICES; do
 /sbin/iptables -A OUTPUT -p udp -m state --state NEW --sport 1:65535 --dport ${PORT} -j LOG  --log-ip-options --log-tcp-options --log-tcp-sequence --log-prefix " Connexion UDP sortant du FW "
 /sbin/iptables -A OUTPUT -p udp -m state --state NEW -s $IP_SRV --sport 1:65535 --dport ${PORT} -j ACCEPT
done
fi

# ICMP est explicitement interdit

if [ $LOGS=oui ] ; then
/sbin/iptables -A INPUT -p icmp -j LOG  --log-ip-options --log-tcp-options --log-tcp-sequence --log-prefix " Tentative d'icmp entrant"
/sbin/iptables -A OUTPUT -p icmp -j LOG  --log-ip-options --log-tcp-options --log-tcp-sequence --log-prefix " Tentative d'icmp sortant"
fi

/sbin/iptables -A INPUT -p icmp -j DROP
/sbin/iptables -A OUTPUT -p icmp -j DROP

# Les flux qui n'ont pas été autorisés auparavant sont loggués 
# (avant d'être supprimés par la politique par défaut)
if [ $LOGS=oui ] ; then
/sbin/iptables -A INPUT -j LOG  --log-ip-options --log-tcp-options --log-tcp-sequence --log-prefix " INPUT Catch-all LOG"
/sbin/iptables -A OUTPUT -j LOG  --log-ip-options --log-tcp-options --log-tcp-sequence --log-prefix " INPUT Catch-all LOG"
fi

# Autres protections réseau
# (certaines valeurs ne fonctionnent que sur certains  noyaux)
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects

#Préconisation ANSSI

# Filtrage  par  chemin  inverse
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
# Ne pas  envoyer  de  redirections  ICMP
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
# Refuser  les  paquets  de  source  routing
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
# Ne pas  accepter  les  ICMP de type  redirect
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
# Loguer  les  paquets  ayant  des IPs  anormales
sysctl -w net.ipv4.conf.all.log_martians=1
# RFC  1337
sysctl -w net.ipv4.tcp_rfc1337=1
# Ignorer  les réponses  non  conformes à la RFC  1122
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
# Augmenter  la plage  pour  les  ports éphémères
sysctl -w net.ipv4.ip_local_port_range=32768  65535
# Utiliser  les SYN  cookies
sysctl -w net.ipv4.tcp_syncookies=1
# Désactiver  le  support  des "router  solicitations"
sysctl -w net.ipv6.conf.all.router_solicitations=0
sysctl -w net.ipv6.conf.default.router_solicitations=0
# Ne pas  accepter  les "router  preferences" par "router  advertisements"
sysctl -w net.ipv6.conf.all.accept_ra_rtr_pref=0
sysctl -w net.ipv6.conf.default.accept_ra_rtr_pref=0
# Pas de  configuration  auto  des  prefix  par "router  advertisements"
sysctl -w net.ipv6.conf.all.accept_ra_pinfo=0
sysctl -w net.ipv6.conf.default.accept_ra_pinfo=0
# Pas d’apprentissage  du  routeur  par défaut  par "router  advertisements"
sysctl -w net.ipv6.conf.all.accept_ra_defrtr=0
sysctl -w net.ipv6.conf.default.accept_ra_defrtr=0
# Pas de  configuration  auto  des  adresses à partir  des "router advertisements"
sysctl -w net.ipv6.conf.all.autoconf=0
sysctl -w net.ipv6.conf.default.autoconf=0
# Ne pas  accepter  les  ICMP de type  redirect
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
# Refuser  les  packets  de  source  routing
sysctl -w net.ipv6.conf.all.accept_source_route=0
sysctl -w net.ipv6.conf.default.accept_source_route=0
# Nombre  maximal d’adresses  autoconfigurées par  interface
sysctl -w net.ipv6.conf.all.max_addresses=1
sysctl -w net.ipv6.conf.default.max_addresses=1

# Désactivation  des  SysReq
sysctl -w kernel.sysrq=0
# Pas de core  dump  des exécutables  setuid
sysctl -w fs.suid_dumpable=0
# Interdiction  de déréférencer  des  liens  vers  des  fichiers  dont
# l’utilisateur  courant n’est pas le  propriétaire
# Peut  empêcher  certains  programmes  de  fonctionner  correctement
sysctl -w fs.protected_symlinks=1
sysctl -w fs.protected_hardlinks=1
# Activation  de l’ASLR
sysctl -w kernel.randomize_va_space=2
# Interdiction  de  mapper  de la mémoire  dans  les  adresses  basses  (0)
sysctl -w vm.mmap_min_addr=65536
# Espace  de choix  plus  grand  pour  les  valeurs  de PID
sysctl -w kernel.pid_max=65536
# Obfuscation  des  adresses mémoire  kernel
sysctl -w kernel.kptr_restrict=1
# Restriction d’accès au  buffer  dmesg
sysctl -w kernel.dmesg_restrict=1
# Restreint l’utilisation  du sous  système perf
sysctl -w kernel.perf_event_paranoid=2
sysctl -w kernel.perf_event_max_sample_rate=1
sysctl -w kernel.perf_cpu_time_max_percent=1

}


fw_routage () {
# Active le  routage  entre  les  interfaces
sysctl -w net.ipv4.ip_forward=1
}

fw_masque () {
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
}

##########################
# Arret du PareFeu 
##########################

fw_stop () {
/sbin/iptables -F
/sbin/iptables -X
/sbin/iptables -t nat -F
/sbin/iptables -t mangle -F
/sbin/iptables -P INPUT DROP
/sbin/iptables -P FORWARD DROP
/sbin/iptables -P OUTPUT DROP
}

##########################
# Parefeu en mode laxist
##########################

fw_laxist () {
/sbin/iptables -F
/sbin/iptables -X
/sbin/iptables -t nat -F
/sbin/iptables -t mangle -F
/sbin/iptables -P INPUT ACCEPT
/sbin/iptables -P FORWARD ACCEPT
/sbin/iptables -P OUTPUT ACCEPT
}

############################
# Redemarrage du PareFeu
############################

fw_restart () {
fw_stop
fw_start
}



case "$1" in
start|restart)
 echo -n "Mise en place des règles du PareFeu IPV4 : "
 fw_restart
 echo "Mise en place terminée."
 ;;
stop)
 echo -n "PareFeu en mode bloquant : "
 fw_stop
 echo "Mise en place terminée."
 ;;
laxist)
 echo -n "PareFeu en mode ouvert : "
fw_laxist
 echo "Mise en place terminée."
 ;;
routage)
 echo -n "Routage activé : "
fw_routage
 echo "Mise en place terminée."
 ;;
masquerade)
 echo -n "Routage activé : "
fw_masque
 echo "Mise en place terminée."
 ;;
*)
 echo "Usage: $0 {start|stop|restart|laxist|routage|masquerade}"
 echo "La fonction stop interdit tous les flux entrants ou sortants."
 echo "La fonction laxist autorise tous les flux entrants ou sortants."
 echo "La fonction routage active le forward entre les différentes interfaces."
 echo "La fonction masquerade... comme son nom l'indique."
 exit 1
 ;;
esac
exit 0


