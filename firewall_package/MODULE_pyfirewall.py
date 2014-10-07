#!/usr/bin/env python
# -*- coding: utf-8 -*- 

# MODULE-NAME:  module_pyfirewall 
# VERSION: (Ver.0.11) Friday, 29 July 2012
#
# DESCRIPTION: functional module by /etc/rc.d/rc.firewall for configurable and
#              personalizable settings
# 
#
# AUTHOR: Gianluca Pernigotto <jeanlucperni@gmail.com>
#  
# Copyright 2012  Gianluca Pernigotto All rights reserved.
# Redistribution and use of this script, with or without modification, is
# permitted provided that the following conditions are met:
#
# 1. Redistributions of this script must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
# EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#######################################################################
from subprocess import Popen, PIPE, call, check_call
import sys, os
import shelve

if os.getuid() != 0:
	print "\n\033[31;1m Permission denied! Are you root?\033[0m\n"
	sys.exit(1)

#us = os.getcwd()
path = "/etc/pyfirewall/0.12/private"

graphicS = '''\033[34;1m
 ------------------------------------------------     
 IP_source:                         HOST_NAME:
 ------------------------------------------------\033[0m'''
 
graphicD = '''\033[34;1m
 ------------------------------------------------     
 IP_dest.:                          HOST_NAME:
 ------------------------------------------------\033[0m'''
 
graphicTCP = '''\033[34;1m
  ------------------------------------------------     
  TCP PORT:                NAME:     TARGETS:
  ------------------------------------------------\033[0m'''
  
graphicUDP = '''\033[34;1m
  ------------------------------------------------     
  UDP PORT:                NAME:     TARGETS:
  ------------------------------------------------\033[0m'''


	
#leggi = open('/etc/pyfirewall/0.11/private/interface.txt','r')
#IFACE = leggi.readline()
#leggi.close()

###################################################################### MENU
def main_menu():
	call('clear', shell = True)
	print """\033[1m 
 NOTA:\n 
     In questo spazio è possibile gestire alcune regole personali nel firewall 
     e tenerne traccia.  
  
     Il blocco dei siti necessita che si conosca l'indirizzo IP ottenibile dal
     comando: "host adress-name" (ottenibile senza i privilegi di amministratore)
     o dal comando "whois adress-name or IP-number". \033[0m
	
  ------------------------------------------------------
		\033[1mBLOCCO INDIRIZZI IP:\033[0m
		
  \033[32;1m|1|\033[0m   Blocca siti non graditi (indirizzo ip)
  \033[32;1m|2|\033[0m   Cancella regole siti non graditi (indirizzo ip)
  \033[32;1m|3|\033[0m   Visualizza la lista dei siti bloccati.  
  -----------------------------------------------------
		\033[1mIMPOSTAZIONI REGOLE TCP/UDP\033[0m
		
  \033[32;1m|4|\033[0m   Aperture/chiusura delle porte sui protocolli tcp/udp
  \033[32;1m|5|\033[0m   Cancella regole precedentemente impostate tcp/udp
  \033[32;1m|6|\033[0m   Visualizza la lista regole tcp/udp
  -----------------------------------------------------
  \033[32;1m|7|\033[0m   Lista tutte le impostazioni globali del firewall
  
  \033[31;1m|Q|\033[0m   Esci\n""" 
	choice = raw_input("Immettere un numero o lettera che corrisponde all'opzione:  > ")
	if choice == '1':
		IP_insert()
	elif choice == '2':
		IP_delete()
	elif choice == '3':
		IP_review()
	elif choice == '4':
		door_connect()
	elif choice == '5':
		door_delete()
	elif choice == '6':
		doors_review()	
	elif choice == '7':
		status()
	elif choice == 'q' or choice == "Q":
		print "pyfirewall, Exit"
		sys.exit()
	else:
		sys.exit("Errore di immissione, Exit.")

####################################################################### IPINSERT
def IP_insert():
	running = True
	while running:
		call('clear', shell = True)
		print '''
  Il blocco di alcuni siti non graditi avviene immettendo la nuova regola
  con l'indirizzo IP. L'indirizzo IP di un sito può essere trovato in vari
  modi: con il comando "host", con il comando "whois" o con il comando
  "dig", seguiti dall'host-name del sito.
  Ogni blocco pù essere eseguito come |s| source, cioè dall'host al proprio
  pc e come |d| destination, cioè dal proprio pc all'host, oppure su entrambi
  i modi. Alcuni siti sono provvisti da più indirizzi IP solitamente con
  numerazione progressiva. Potrebbe essere opportuno immettere un intervallo
  per esempio: 192.000.000.20/192.000.000.24 per coprire il range.
  Svuotare i dati dal proprio browser rende effettiva la nuova regola. 
'''
###### |s| insert
		iptarget = raw_input("\n\n\033[1m Scrivi qui l'ip da bloccare, ['q' per tornare al menu iniziale]\033[0m >  ")
		if iptarget == 'q' or iptarget == 'Q':
			running = False
			main_menu()
		description = raw_input("\n\n\033[1m Immettere qui l'adress-name o una breve descrizione del sito.\n\033[0m >  ")			
		opt = raw_input("\n\n\033[1m Opzioni da applicare: \033[32;1m|s|\033[0m = source / \033[32;1m|d|\033[0m = destination\033[0m / \033[32;1m|sd|\033[0m = entrambi.\033[0m >  ")
		
		if opt == "s" or opt == "S":  # source è il blocco in entrata
			diz = shelve.open('%s/s_block.db'% path,'c') 
			if diz.has_key(iptarget) is False:
				diz[iptarget] = description
				check_call('iptables -I INPUT -s %s -j DROP' % (key), shell = True)
				#print "check_call('iptables -D INPUT -s %s -j DROP', shell = True)" % iptarget
				addipS = "\n\033[1m |S| SOURCE: Regola di 'blocco IP' impostata nel firewall.\033[0m"
			else:
				addipS = "\n\033[31;1m |S| SOURCE: Questa regola di 'blocco IP' risulta già impostata.\033[0m"
							
			print graphicS
			for key,val in diz.items():
				print("\033[36m  [%s]      --     %s\033[0m" % (str(key), str(val)) )
			print addipS
			diz.close()
			raw_input("\n\033[1m Premi invio per continuare:\033[0m")
###### |d| insert			
			
		elif opt == "d" or opt == "D":  # d: destination è il blocco in uscita
			diz = shelve.open('%s/d_block.db'% path,'c') 
			if diz.has_key(iptarget) is False:
				diz[iptarget] = description
				check_call('iptables -A OUTPUT -d %s -j DROP' % (iptarget), shell = True)
				#print "check_call('iptables -A OUTPUT -d %s -j DROP', shell = True)" % iptarget
				addipD = "\n\033[1m |D| DESTINATION: Regola di 'blocco IP' impostata nel firewall.\033[0m"
			else:
				addipD = "\n\033[31;1m |D| DESTINATION: Questa regola di 'blocco IP' risulta già impostata.\033[0m"
			
			print graphicD
			for key,val in diz.items():
				print("\033[36m  [%s]      --     %s\033[0m" % (str(key), str(val)) )
			print addipD
			diz.close()
			raw_input("\n\033[1m Premi invio per continuare:\033[0m")
######	|s|d| insert
						
		elif opt == "sd" or opt == "SD":  
			diz1 = shelve.open('%s/s_block.db'% path,'c')
			diz2 = shelve.open('%s/d_block.db'% path,'c') 
			if diz1.has_key(iptarget) is False:
				diz1[iptarget] = description
				check_call('iptables -I INPUT -s %s -j DROP' % (iptarget), shell = True)
				#print "check_call('iptables -I INPUT -s %s -j DROP', shell = True)" % iptarget
				addipS = "\n\033[1m |S| SOURCE: Regola di 'blocco IP' impostata nel firewall.\033[0m"
			else:
				addipS = "\n\033[31;1m |S| SOURCE: Questa regola di 'blocco IP' risulta già impostata.\033[0m"				
			if diz2.has_key(iptarget) is False:
				diz2[iptarget] = description
				check_call('iptables -A OUTPUT -d %s -j DROP' % (iptarget), shell = True)
				#print "check_call('iptables -A OUTPUT -d %s -j DROP', shell = True)" % iptarget
				addipD = "\n\033[1m |D| DESTINATION: Regola di 'blocco IP' impostata nel firewall.\033[0m"
			else:
				addipD = "\n\033[31;1m |D| DESTINATION: Questa regola di 'blocco IP' risulta già impostata.\033[0m"			
			print graphicS			
			for key,val in diz1.items():
				print("\033[36m  [%s]      --     %s\033[0m" % (str(key), str(val)) )				
			print graphicD			
			for key,val in diz2.items():
				print("\033[36m  [%s]      --     %s\033[0m" % (str(key), str(val)) )
			print addipS
			print addipD
			diz1.close()
			diz2.close()
			raw_input("\n\033[1m Premi invio per continuare:\033[0m")
###### insert

		else:
			running = False
			sys.exit("\n\n\033[31;1mBad option, no match (s? d? sd?)\033[0m")
			
	
############################################################################ DELETES IP
def IP_delete():
	running = True
	while running:
		call('clear', shell = True)
		print '''
  La procedura per rimuovere le regole precedentemente sottoscritte av-
  viene similmente a quella della loro sottoscrizione, cioè immettendo
  l'indirizzo IP e indicando il match (|s| o |d|).
  Per vedere quali regole sono già state sottoscritte, tornare al menu
  e usare l'opzione che visualizza la loro lista. 
'''

		iptarget = raw_input("\n\n\033[1m Scrivi qui l'ip da sbloccare, ['q' per terminare]\033[0m >  ")
		if iptarget == 'q' or iptarget == 'Q':
			running = False
			main_menu()
			
		opt = raw_input("\n\n\033[1m Opzioni di scelta: \033[32;1m|s|\033[0m = source / \033[32;1m|d|\033[0m = destination\033[0m / \033[32;1m|sd|\033[0m = entrambi.\033[0m >  ")
#### |s| delete		
		if opt == "s" or opt == "S":  
			diz = shelve.open('%s/s_block.db'% path,'c') 
			
			if diz.has_key(iptarget):
				del diz[iptarget]
				#print "check_call('iptables -D INPUT -s %s -j DROP', shell = True)" % iptarget
				check_call('iptables -D INPUT -s %s -j DROP' % iptarget, shell = True)
				delipS = "\n\033[1m |S| SOURCE: Regola di 'blocco IP' cancellata nel firewall.\033[0m"
			else:
				delipS =  "\n\033[31;1m |S| SOURCE: regola inesistente\033[0m"
				
			print graphicS
			for key,val in diz.items():
				print("\033[36m  [%s]      --     %s\033[0m" % (str(key), str(val)) )
			print delipS
			diz.close()
			raw_input("\n\n\033[1m Premi invio per continuare:\033[0m")
			
#### |d| delete			
			
		elif opt == "d" or opt == "D":  
			diz = shelve.open('%s/d_block.db'% path,'c')
			
			if diz.has_key(iptarget):
				del diz[iptarget]
				#print "check_call('iptables -D OUTPUT -d %s -j DROP', shell = True)" % iptarget
				check_call('iptables -D OUTPUT -d %s -j DROP' % iptarget, shell = True)
				delipD = "\n\033[1m |D| DESTINATION: Regola di 'blocco IP' cancellata nel firewall.\033[0m"
			else:
				delipD = "\n\033[31;1m |D| DESTINATION: regola inesistente\033[0m"																	
			print graphicD
			for key,val in diz.items():
				print("\033[36m  [%s]      --     %s\033[0m" % (str(key), str(val)) )
			print delipD
			diz.close()
			raw_input("\n\n\033[1m Premi invio per continuare:\033[0m")
			
			
######	|s|d| delete	
						
		elif opt == "sd" or opt == "SD":  
			diz1 = shelve.open('%s/s_block.db'% path,'c')
			diz2 = shelve.open('%s/d_block.db'% path,'c') 

			if diz1.has_key(iptarget):
				del diz1[iptarget]
				check_call('iptables -D INPUT -s %s -j DROP' % (iptarget), shell = True)
				#print "check_call('iptables -D INPUT -s %s -j DROP', shell = True)" % iptarget
				delipS = "\n\033[1m |S| SOURCE: Regola di 'blocco IP' cancellata nel firewall.\033[0m"
			else:
				delipS = "\n\033[31;1m |S| SOURCE: regola inesistente\033[0m"
				
			if diz2.has_key(iptarget):
				del diz2[iptarget]
				check_call('iptables -D OUTPUT -d %s -j DROP' % (iptarget), shell = True)
				#print "check_call('iptables -A OUTPUT -d %s -j DROP', shell = True)" % iptarget
				delipD = "\n\033[1m |D| DESTINATION: Un blocco ip  è stato cancellato.\033[0m"
			else:
				delipD = "\n\033[31;1m |D| DESTINATION: regola inesistente\033[0m"
				
			print graphicS			
			for key,val in diz1.items():
				print("\033[36m  [%s]      --     %s\033[0m" % (str(key), str(val)) )
				
			print graphicD			
			for key,val in diz2.items():
				print("\033[36m  [%s]      --     %s\033[0m" % (str(key), str(val)) )
			print delipS
			print delipD
			diz1.close()
			diz2.close()
			raw_input("\n\n\033[1m Premi invio per continuare:\033[0m")
#### err delete						
		else:
			running = False
			sys.exit("\n\n\033[31;1mBad option, no match (s? d? sd?)\033[0m")
			
		
#######################################################################  REVIEWs
def IP_review():
	diz = shelve.open('%s/s_block.db'% path,'c') 
	print '''\033[1m   LISTA IP BLOCCATI \033[0m 
\033[34;1m
  ------------------------------------------------     
  IP sources:                         HOST_NAME:
  ------------------------------------------------\033[0m'''
	for key,val in diz.items():
		print("\033[36m  [%s]      --     %s\033[0m" % (str(key), str(val)) )
	diz.close()
		
	diz = shelve.open('%s/d_block.db'% path,'c') 
	print '''\033[34;1m
  ------------------------------------------------     
  IP destination:                     HOST_NAME:
  ------------------------------------------------\033[0m'''
	for key,val in diz.items():
		print("\033[36m  [%s]      --     %s\033[0m" % (str(key), str(val)) )
	diz.close()
	raw_input('\033[34;1mPremi invio per continuare\033[0m')
	main_menu()
	
####################################################################### STATUS
def status():
	print "\033[34;1m=========================================================================\033[0m"
	print "\033[36m"
	check_call('iptables -nvL', shell=True)
	print ""
	print "\033[34;1m=========================================================================\033[0m"
	sys.exit()


####################################################################### TCP/UDP OPEN

def door_connect():
	call('clear', shell = True)
	print '''
  Le porte TCP/UDP sono tutte controllate dalle nuove chain (-N TCP, -N UDP)
  impostate in modo predefinito nel firewall. Tuttavia è possibile operare 
  per poter aprire/chiudere determinate porte o eliminare delle regole.
  Ogni regola è costituita da tre target (drop, accept, reject) che deter-
  minano l'azione sulla porta: drop rifiuta e scarta il pacchetto, accept
  lo consente e reject lo respinge al mittente.
  Qui le porte devono essere indicate con un numero (o una lista di numeri 
  delimitati da una virgola fino ad un massimo di 15) o un range (8990:9000), 
  dei protocolli e un target.
  
  esempi:
  
  NUMERO: 6890 
  LISTA DI NUMERI: 22,25,53,80,433,465,5222,5269,5280,8999:9003
  PROTOCOLLO: TCP, UDP o TCP/UDP
  TARGET: drop (chiude la porta)
          accept (apre la porta)
          reject ( chiude la porta e respinge al mittente)
          
  NOTA: per includere un range o intervallo di porte usa per esempio 6890:6895
'''
	doortarget = raw_input("\n\n\033[1m Numero porta da sottoscrivere nelle regole del firewall\n\033[0m >  ")
	
	if str.isdigit(doortarget) is False:
		sys.exit("\n\n\033[31;1mBad option, is not integer\033[0m")
			
	description = raw_input("\n\n\033[1m Descrizione del servizio di appartenenza\n\033[0m >  ")			
	opt = raw_input("\n\n\033[1m Tipo di Protocollo connessione: \033[32;1m|tcp|\033[0m / \033[32;1m|udp|\033[0m / \033[32;1m|tcp/udp|\033[0m >  ")
	target = raw_input("\n\n\033[1m Regola da applicare :\033[32;1m|1|\033[0m(drop) \033[32;1m|2|\033[0m(reject) \033[32;1m|3|\033[0m(accept):\033[0m > N°  ")
	if target == "1":
		target = "DROP"

	elif target == "2":
		target = "REJECT" 

	elif target == "3":
		target = "ACCEPT"
	else:
		sys.exit("\n\n\033[31;1mBad option, invalid target\033[0m")
		
##### |TCP| insert

	if opt == "tcp" or opt == "TCP":  
		diz = shelve.open('%s/tcp_connect.db'% path,'c')		

		if diz.has_key(doortarget) is False:
			pass
		else:
			rule = diz[doortarget]
			print "\n\n\033[31;1m La porta TCP %s è già stata sottoscritta alla regola %s.\n Se si intende procedere verrà sovrascritta da quella nuova:  \033[0m" % (doortarget, rule[1])
			answer = raw_input("\n\033[1m Procedere? |y|n|.\033[0m >  ")
			if answer == "y" or answer == "Y":
				#print "check_call('iptables -D TCP -p tcp --dport %s -j %s', shell = True)" % (doortarget, rule[1])
				check_call('iptables -D TCP -p tcp -m multiport --dport %s -j %s' % (doortarget, rule[1]), shell = True)
				del diz [doortarget]
			elif answer == "n" or answer == "N":
				diz.close()
				main_menu()
			else:
				sys.exit("\n\n\033[31;1mBad option, invalid input\033[0m")
						
		diz[doortarget] = description,"%s" % target
		#print "check_call('iptables -A TCP -p tcp --dport %s -j %s', shell = True)" % (doortarget,target)
		check_call('iptables -A TCP -p tcp -m multiport --dport %s -j %s' %(doortarget,target), shell = True) 
		
		print graphicTCP
		for key,val in diz.items():
			print("\033[36m  [%s]        --       %s\033[0m" % (str(key), str(val)) )
		diz.close()
		print "\n\033[1m |TCP|: Porta '%s' del Servizio '%s' è appesa alla regola '%s' nel firewall.\033[0m" %(doortarget,description,target)
		raw_input("\n\033[1m Premi invio per continuare:\033[0m")
		main_menu()
		
##### |UDP| insert			
						
	elif opt == "udp" or opt == "UDP":  
		diz = shelve.open('%s/udp_connect.db'% path,'c') 
		
		if diz.has_key(doortarget) is False:
			pass
		else:
			rule = diz[doortarget]
			print "\n\n\033[31;1m La porta UDP %s è già stata sottoscritta alla regola %s.\n Se si intende procedere verrà sovrascritta da quella nuova:  \033[0m" % (doortarget, rule[1])
			answer = raw_input("\n\033[1m Procedere? |y|n|.\033[0m >  ")
			if answer == "y" or answer == "Y":
				#print "check_call('iptables -D UDP -p udp --dport %s -j %s', shell = True)" % (doortarget, rule[1])
				check_call('iptables -D UDP -p udp -m multiport --dport %s -j %s' % (doortarget, rule[1]), shell = True)
				del diz [doortarget]
			elif answer == "n" or answer == "N":
				diz.close()
				main_menu()
			else:
				sys.exit("\n\n\033[31;1mBad option, invalid input\033[0m")
				
		diz[doortarget] = description,"%s" % target
		#print "check_call('iptables -A UDP -p udp --dport %s -j %s', shell = True)" % (doortarget,target)
		check_call('iptables -A UDP -p udp -m multiport --dport %s -j %s' %(doortarget,target), shell = True) 
		
		print graphicUDP
		for key,val in diz.items():
			print("\033[36m  [%s]        --       %s\033[0m" % (str(key), str(val)) )
		diz.close()
		print "\n\033[1m |UDP|: Porta '%s' del Servizio '%s' è appesa alla regola '%s' nel firewall.\033[0m" %(doortarget,description,target)
		raw_input("\n\033[1m Premi invio per continuare:\033[0m")
		main_menu()
		
##### |TCP/UDP| insert

	elif opt == "tcp/udp" or opt == "TCP/UDP":			
		diz1 = shelve.open('%s/tcp_connect.db'% path,'c')
		diz2 = shelve.open('%s/udp_connect.db'% path,'c') 
		
		if diz1.has_key(doortarget) is False:
			EXEC1 = '1'
		else:
			ruleTCP = diz1[doortarget]
			print "\n\n\033[31;1m La porta TCP %s è già stata sottoscritta alla regola %s.\n Se si intende procedere verrà sovrascritta da quella nuova:  \033[0m" % (doortarget, ruleTCP[1])
			answer = raw_input("\n\033[1m Procedere? |y|n|.\033[0m >  ")
			if answer == "y" or answer == "Y":
				#print "check_call('iptables -D TCP -p tcp --dport %s -j %s', shell = True)" % (doortarget, ruleTCP[1])
				check_call('iptables -D TCP -p tcp -m multiport --dport %s -j %s' % (doortarget, ruleTCP[1]), shell = True)
				del diz1 [doortarget]
				EXEC1 = '1'
				
			elif answer == "n" or answer == "N":
				EXEC1 = '0'				
			else:
				sys.exit("\n\n\033[31;1mBad option, invalid input\033[0m")
				
		if EXEC1 == '1':
			diz1[doortarget] = description,"%s" % target
			#print "check_call('iptables -A TCP -p tcp --dport %s -j %s', shell = True)" % (doortarget,target)
			check_call('iptables -A TCP -p tcp -m multiport --dport %s -j %s' %(doortarget,target), shell = True)
			addTCP =  "\n\033[1m |TCP|: Porta '%s' del Servizio '%s' è appesa alla regola '%s' nel firewall.\033[0m" %(doortarget,description,target)
		elif EXEC1 == '0':
			addTCP = "\n\033[31;1m |TCP|: Regola esistente invariata (porta:%s servizio:%s regola:%s).\033[0m" % (doortarget, ruleTCP[0], ruleTCP[1])
			
#============================================================							
				
		if diz2.has_key(doortarget) is False:
			EXEC2 = '1'
		else:
			ruleUDP = diz2[doortarget]
			print "\n\n\033[31;1m La porta UDP %s è già stata sottoscritta alla regola %s.\n Se si intende procedere verrà sovrascritta da quella nuova:  \033[0m" % (doortarget, ruleUDP[1])
			answer = raw_input("\n\033[1m Procedere? |y|n|.\033[0m >  ")
			if answer == "y" or answer == "Y":
				#print "check_call('iptables -D UDP -p udp --dport %s -j %s', shell = True)" % (doortarget, ruleUDP[1])
				check_call('iptables -D UDP -p udp -m multiport --dport %s -j %s' % (doortarget, ruleUDP[1]), shell = True)
				del diz2 [doortarget]
				EXEC2 = '1'				
			elif answer == "n" or answer == "N":				
				EXEC2 = '0'
			else:
				sys.exit("\n\n\033[31;1mBad option, invalid input\033[0m")
		if EXEC2 == '1':
			diz2[doortarget] = description,"%s" % target
			#print "check_call('iptables -A UDP -p udp --dport %s -j %s', shell = True)" % (doortarget,target)
			check_call('iptables -A UDP -p udp -m multiport --dport %s -j %s' %(doortarget,target), shell = True)
			addUDP = "\n\033[1m |UDP|: Porta '%s' del Servizio '%s' è appesa alla regola '%s' nel firewall.\033[0m" %(doortarget,description,target)
		elif EXEC2 == '0':
			addUDP = "\n\033[31;1m |UDP|: Regola esistente invariata (porta:%s servizio:%s regola:%s).\033[0m" % (doortarget, ruleUDP[0], ruleUDP[1])
		
				
		print graphicTCP
		for key,val in diz1.items():
			print("\033[36m  [%s]        --       %s\033[0m" % (str(key), str(val)) )
			
		print graphicUDP
		for key,val in diz2.items():
			print("\033[36m  [%s]        --       %s\033[0m" % (str(key), str(val)) )
		print addTCP
		print addUDP
		diz1.close()
		diz2.close()
		raw_input("\n\033[1m Premi invio per continuare:\033[0m")
		main_menu()
		
##### end TCP insert				
	else:
		sys.exit("\n\n\033[31;1mBad option, invalid protocol (tcp? udp?)\033[0m")
	
	
############################################################################ DELETES TCP/UDP
def door_delete():
	call('clear', shell = True)
	print '''\n
  \033[31;1mCANCELLAZIONE REGOLE SUI PROTOCOLLI TCP/UDP\033[0m
  
  La procedura per rimuovere le regole precedentemente sottoscritte av-
  viene similmente a quella della loro sottoscrizione, cioè immettendo
  il numero della porta TCP o UDP che sottointende la regola da eliminare.
  Per vedere quali regole sono già state sottoscritte, tornare al menu
  e usare l'opzione che visualizza la loro lista.
'''
	doortarget = raw_input("\n\n\033[1m Numero porta da cancellare dalle regole del firewall\n\033[0m >  ")
	opt = raw_input("\n\n\033[1m Tipo di Protocollo connessione: \033[32;1m|tcp|\033[0m / \033[32;1m|udp|\033[0m / \033[32;1m|tcp/udp|\033[0m >  ")
	
##### |TCP| delete

	if opt == "tcp" or opt == "TCP":  
		diz = shelve.open('%s/tcp_connect.db'% path,'c')   
		if diz.has_key(doortarget) is True:
			pass
		else:
			print "\n\033[31;1m |TCP|: regola inesistente nel firewall\033[0m"
			raw_input("\n\n\033[1m\n Premi invio per tornare al menu iniziale:\033[0m")
			diz.close()
			main_menu()
		rule = diz[doortarget]
		check_call('iptables -D TCP -p tcp -m multiport --dport %s -j %s' %(doortarget,rule[1]), shell = True)
		#print "check_call('iptables -D TCP -p tcp --dport %s -j %s', shell = True)" %(doortarget,rule[1])
		del diz[doortarget]
		delTCP = "\n\033[1m |TCP|: (Porta:'%s', Servizio:'%s', Target:'%s') Regola cancellata nel firewall.\033[0m" % (doortarget, rule[0], rule[1])
		print graphicTCP
		for key,val in diz.items():
			print("\033[36m  [%s]        --       %s\033[0m" % (str(key), str(val)) )
		diz.close()
		print delTCP
		raw_input("\n\n\033[1m Premi invio per continuare:\033[0m")
		main_menu()
		
##### |UDP| delete		
		
	elif opt == "udp" or opt == "UDP":  
		diz = shelve.open('%s/udp_connect.db'% path,'c')   
		if diz.has_key(doortarget) is True:
			pass
		else:
			print "\n\033[31;1m |UDP|: regola inesistente nel firewall\033[0m"
			raw_input("\n\n\033[1m\n Premi invio per tornare al menu iniziale:\033[0m")
			diz.close()
			main_menu()
		rule = diz[doortarget]
		check_call('iptables -D UDP -p udp -m multiport --dport %s -j %s' %(doortarget,rule[1]), shell = True)
		#print "check_call('iptables -D UDP -p udp --dport %s -j %s', shell = True)" %(doortarget,rule[1])
		del diz[doortarget]
		delUDP = "\n\033[1m |UDP|: (Porta:'%s', Servizio:'%s', Target:'%s') Regola cancellata nel firewall.\033[0m" % (doortarget, rule[0], rule[1])
		print graphicUDP
		for key,val in diz.items():
			print("\033[36m  [%s]        --       %s\033[0m" % (str(key), str(val)) )
		diz.close()
		print delUDP
		raw_input("\n\n\033[1m Premi invio per continuare:\033[0m")
		main_menu()
		
##### |TCP/UDP| delete		
		
	elif opt == "tcp/udp" or opt == "TCP/UDP":  
		diz1 = shelve.open('%s/tcp_connect.db'% path,'c')
		diz2 = shelve.open('%s/udp_connect.db'% path,'c')
						
		if diz1.has_key(doortarget) is True:
			ruleTCP = diz1[doortarget]
			delTCP = "\n\033[1m |TCP|: (Porta:'%s', Servizio:'%s', Target:'%s') Regola cancellata nel firewall.\033[0m" % (doortarget, ruleTCP[0], ruleTCP[1])			
			check_call('iptables -D TCP -p tcp -m multiport --dport %s -j %s' %(doortarget,ruleTCP[1]), shell = True)
			#print "check_call('iptables -D TCP -p tcp --dport %s -j %s', shell = True)" %(doortarget,ruleTCP[1])			
			del diz1[doortarget]
		else:
			delTCP = "\n\033[31;1m |TCP|: regola inesistente nel firewall\033[0m"
					
		if diz2.has_key(doortarget) is True:
			ruleUDP = diz2[doortarget]
			delUDP = "\n\033[1m |UDP|: (Porta:'%s', Servizio:'%s', Target:'%s') Regola cancellata nel firewall.\033[0m" % (doortarget, ruleUDP[0], ruleUDP[1])			
			check_call('iptables -D UDP -p udp -m multiport --dport %s -j %s' %(doortarget,ruleUDP[1]), shell = True)
			#print "check_call('iptables -D UDP -p udp --dport %s -j %s', shell = True)" %(doortarget,ruleUDP[1])
			del diz2[doortarget]		
		else:
			delUDP = "\n\033[31;1m |UDP|: regola inesistente nel firewall\033[0m"
						
		print graphicTCP
		for key,val in diz1.items():
			print("\033[36m  [%s]        --       %s\033[0m" % (str(key), str(val)) )
		print graphicUDP
		for key,val in diz2.items():
			print("\033[36m  [%s]        --       %s\033[0m" % (str(key), str(val)) )		
		print delTCP
		print delUDP
		diz1.close()
		diz2.close()
		raw_input("\n\n\033[1m\n Premi invio per tornare al menu iniziale:\033[0m")
		main_menu()
		
##### |TCP/UDP| err delete

	else:
		sys.exit("\n\n\033[31;1mBad option, invalid protocol (tcp? udp? tcp/udp?)\033[0m")	
	

#######################################################################  REVIEW TCP/UDP
def doors_review():
	call('clear', shell = True)
	diz = shelve.open('%s/tcp_connect.db'% path,'c') 
	print '''\033[1m   LISTA REGOLE PORTE TCP/UDP \033[0m
\033[34;1m
                 lista regole attive:
  ------------------------------------------------     
  TCP PORT:                NAME:     TARGETS:
  ------------------------------------------------\033[0m'''
	for key,val in diz.items():
		print("\033[36m  [%s]        --       %s\033[0m" % (str(key), str(val)) )
	diz.close()
		
	diz = shelve.open('%s/udp_connect.db'% path,'c') 
	print '''\033[34;1m
  ------------------------------------------------     
  UDP PORT:                NAME:     TARGETS:
  ------------------------------------------------\033[0m'''
	for key,val in diz.items():
		print("\033[36m  [%s]        --       %s\033[0m" % (str(key), str(val)) )
	diz.close()
	raw_input('\033[34;1mPremi invio per tornare al menu..\033[0m')
	main_menu()
	
#######################################################################  LOADs	PROVA FUOCO	
			
def load_all():
	diz = shelve.open('%s/s_block.db'% path,'c') 
	if len(diz) <= 0:
		diz.close()
		#print "\033[1m[BlackList] Nessuna regola di blocco IP impostata in entrata ..ok\033[0m"
		
	else:
		#print "Attivo blocco IP [in] personale"		
		for key in diz.keys():
			check_call('iptables -I INPUT -s %s -j DROP' % (key), shell = True)
			#print "check_call(iptables -I INPUT -s %s -j DROP " % key
		diz.close()
					
	diz = shelve.open('%s/d_block.db'% path,'c') 
	if len(diz) <= 0:
		diz.close()
		#print "\033[1m[BlackList] Nessuna regola di blocco IP impostata in uscita ..ok\033[0m"
		
	else:
		#print "Attivo blocco IP [out] personale"		
		for key in diz.keys():
			check_call('iptables -A OUTPUT -d %s -j DROP' % (key), shell = True)
			#print "check_call(iptables -A INPUT -s %s -j DROP " % key
		diz.close()
	
	diz = shelve.open('%s/tcp_connect.db'% path,'c') 
	if len(diz) <= 0:
		#print "\033[1m Nessuna regola TCP impostata ..ok\033[0m"
		diz.close()		
	else:
		#print "Attivo apertura connessione TCP personale"		
		val = diz.values()
		tupla = val[0]
		for key in diz.keys():
			check_call('iptables -A TCP -p tcp --dport %s -j %s' %(key, tupla[1]), shell = True)
			#print "check_call(iptables -A TCP -p tcp --dport %s -j %s" %(key, tupla[1])
		diz.close()
					
	diz = shelve.open('%s/udp_connect.db'% path,'c') 
	if len(diz) <= 0:
		#print "\033[1m Nessuna regola UDP impostata ..ok\033[0m"
		diz.close()
		sys.exit()
	else:
		#print "Attivo apertura connesione UDP personale"
		val = diz.values()
		tupla = val[0]
		for key in diz.keys():
			check_call('iptables -A UDP -p udp --dport %s -j %s' %(key, tupla[1]), shell = True)
			#print "check_call(iptables -A UDP -p udp --dport %s -j %s" %(key, tupla[1])
		diz.close()
		sys.exit()



