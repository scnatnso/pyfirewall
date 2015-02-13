NOME PROGRAMMA: 
 
pyfirewall

DIPENDENZE:
 
python=2.6 >, iptables


DESCRIZIONE:

Pyfirewall è un programma firewall (statefull) basato su iptables, senza 
interfaccia grafica, scritto in python, che filtra e limita i pacchetti 
che attraversano la rete internet tutelando così il proprio ambiente Gnu/
Linux. E' configurato per funzionare con ogni tipo di interfaccia di rete 
(eth e wireless, vedere FEATURES più sotto) di un singolo pc in una normale 
rete adsl domestica.

Offre veloci possibilità di personalizzazione quali blocco degli IP 
(source e destination) e impostazioni porte tcp/udp (drop, accept, reject
= chiusura, apertura, scarta pacchetto e invia lo stato)
ed eventuale eliminazione di ogni personale regola impostata. 

L'algoritmo del programma sta nel trovare e leggere i dati memorizzati
nei sui database creati durante l'installazione (inizialmente vuoti).
Al momento, gli elenchi di regole che l'utente può passargli riguardano 
il blocco IP e le impostazioni sulle porte TCP/UDP, le quali vengono 
applicate al momento stesso della sottoscrizione e quindi caricate ad ogni 
riavvio del sistema.
      
 NOTE:

Lo scrip di avvio viene installato in /etc/rc.d/
rc.firewall su Slackware e su /etc/init.d/firewall su Debian.
Per lanciarlo dal terminale basta il comando 'pyfirewall' come 
utente root (amministratore).

Se il programma/firewall non parte, controllare i permessi dello script
in rc.d ed eventualmente dare: chmod +x /etc/rc.d/rc.firewall


!! IMPORTANTE !! ********* !! IMPORTANTE !! ********* !! IMPORTANTE !! :

Durante il processo di installazione viene creato il file di configurazione
"sysctl.conf" in /etc con i parametri settati per incrementare la sicurezza della
rete. Se nel corso dell'installazione esistesse un altro file in /etc con lo 
stesso nome, esso verrà salvato come "sysctl.conf.orig", pertanto si tenga 
conto di questo per una eventuale copia di backup o recupero in tal modo da 
poter ricopiare eventualmente qualche riga con i propri parametri personali 
nel nuovo file di configurazione!
   
  

 FEATURES:

Simple Stateful Firewall.
Inspirato a "https://wiki.archlinux.org/index.php/Simple_stateful_firewall" 

 
###############
INPOSTAZIONI BASILARI
###############

1.     Carico dei moduli del Kernel:

ip_tables
iptable_nat
ip_conntrack
ip_conntrack_ftp
ip_nat_ftp
ipt_LOG
ipt_MARK
ipt_MASQUERADE
ipt_REDIRECT
ipt_REJECT
ipt_TOS
ipt_limit
ipt_mac
ipt_mark
ipt_multiport
ipt_state
ipt_tos
iptable_mangle


2.     Reset delle impostazioni 



3. Creazione nuove chains 

-N TCP
-N UDP


4.     Impostazione Policy standard 

-P INPUT   DROP
-P FORWARD DROP
-P OUTPUT  ACCEPT



###############
REGOLE PREDEFINITE:
###############

 1. Abilitazione traffico in entrata solo se relativo a pacchetti in risposta #


 2. Abilitazione traffico interno #


 3. La terza regola droppa tutto il traffico in uno stato di confronto "INVALID".
    Il traffico può avvenire in quattro categorie di "stato": nuovo, stabilito, 
    relativivo o invalido


 4. La regola successiva accetta tutte le nuove richieste in arrivo echo ICMP, 
    noto anche come ping.


 5. aggiunte le catene aperte alla catena INPUT per gestire tutte le nuove 
    connessioni in entrata


 6. rifiuto delle connessioni TCP con i pacchetti TCP RST e flussi UDP con 
    messaggi ICMP port unreachable se le porte non si aprono

 7. Per altri protocolli è stata aggiunta una regola definitiva alla catena 
    INPUT per respingere tutto il traffico rimanente in entrata con messaggi 
    del protocollo icmp irraggiungibili. Questo imita il comportamento 
    predefinito di Linux. 


##############################
IMPOSTAZIONI PARAMETRI DI SETTAGGIO SUL FILE sysctl.conf
TCP/IP stack hardening 
##############################

 1. [rp_filter = enable]
    - Protezione contro attacchi di spoofing, pacchetti log martians
  
 2. [tcp_syncookies = enable]
    - protezione TCP SYN cookies: protegge contro gli attacchi SYN flood 
 
 3. [icmp_ignore_bogus_error_responses = enable]
    - RIFIUTO Pacchetti con reindirizzamento di percorso ICMP: ignora falsi 
      errori ICMP
  
 4. [log_martians = enable]
    - log dei pacchetti spoofed, source routed e redirect
  
 5. [accept_source_route = disable]
    - Disabilitazione dei pacchetti source route 

 6. [accept_redirects = disable] 
    [secure_redirects = enable]
    - Rifiuto di rispondere ai ping inviati all'indirizzo broadcast della rete: 
      ICMP di routing redirect (solo sicuro)

 7. [send_redirects = disable]
    - Do not send ICMP redirects (we are not a router)

 8. [icmp_echo_ignore_all = enable]
    - optionally, ignore all echo requests
