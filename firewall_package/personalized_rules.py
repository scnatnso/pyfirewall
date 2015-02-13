#!/usr/bin/env python
# -*- coding: utf-8 -*- 
#
# 
#########################################################
# Name: personalized_rules.py
# Porpose: Management of custom rules and storage iptables settings
# Writer: Gianluca Pernigoto <jeanlucperni@gmail.com>
# Copyright: (c) 2013-2015 Gianluca Pernigoto <jeanlucperni@gmail.com>
# license: GPL3
# Version: (Ver.0.11) Friday, 29 July 2012
# Rev (v0.13) 04/002/2015
#########################################################

"""
This is a functional module called by /etc/rc.d/rc.firewall.
It use shelve (a persistent, dictionary-like object) for storage 
settings which need to be applicate.

"""

from subprocess import Popen, PIPE, call, check_call
import sys, os
import shelve

#if os.getuid() != 0:
	#print "\n\033[31;1m Permission denied! Are you root?\033[0m\n"
	#sys.exit(1)

path = "/etc/pyfirewall/0.12/private"

graphic_address_block = '''\033[34;1m
 ------------------------------------------------     
 KEY WORD:                         DESCRIPTION:
 ------------------------------------------------\033[0m'''
 
graphic_rules_TCP = '''\033[34;1m
  ------------------------------------------------     
  TCP PORT:                NAME:     TARGETS:
  ------------------------------------------------\033[0m'''
  
graphic_rules_UDP = '''\033[34;1m
  ------------------------------------------------     
  UDP PORT:                NAME:     TARGETS:
  ------------------------------------------------\033[0m'''
  
#TEST
#leggi = open('/etc/pyfirewall/0.11/private/interface.txt','r')
#IFACE = leggi.readline()
#leggi.close()

###################################################################### MENU
def main_menu(version):
	"""
	show description and menu choice called with 'pyfirewall settings' param.
	"""
	call('clear', shell = True)
	print """\033[1m 
     In questo spazio è possibile gestire alcune regole personali
     nel firewall e tenerne traccia.\033[0m
     
     inserire numero o lettera opzionali:
     

  ------------------------------------------------------
        \033[1mBLOCCO DEI SITI WEB NON GRADITI:\033[0m

  \033[32;1m|1|\033[0m   Blocca siti non graditi
  \033[32;1m|2|\033[0m   Cancella regole siti non graditi
  \033[32;1m|3|\033[0m   Visualizza la lista dei siti bloccati.  
  -----------------------------------------------------
        \033[1mIMPOSTAZIONI REGOLE TCP/UDP\033[0m

  \033[32;1m|4|\033[0m   Aperture/chiusura delle porte sui protocolli tcp/udp
  \033[32;1m|5|\033[0m   Cancella regole precedentemente impostate tcp/udp
  \033[32;1m|6|\033[0m   Visualizza la lista regole tcp/udp
  -----------------------------------------------------
  \033[32;1m|7|\033[0m   Lista tutte le impostazioni globali del firewall
  
  \033[31;1m|Q|\033[0m   Esci\n""" 
  
	choice = raw_input("Attendo un input che corrisponde all'opzione:  > ")

	if choice == '1':
		IP_insert(version)
	elif choice == '2':
		IP_delete(version)
	elif choice == '3':
		IP_review(version)
	elif choice == '4':
		door_connect(version)
	elif choice == '5':
		door_delete(version)
	elif choice == '6':
		doors_review(version)
	elif choice == '7':
		status()
	elif choice == 'q' or choice == "Q":
		print "pyfirewall, Exit"
		sys.exit()
	else:
		sys.exit("Errore di immissione, Exit.")

################################################ BLOCK IP APPEND
def IP_insert(path):
	"""
	Block the undesired web sites addresses
	"""
	running = True
	
	while running:
		
		call('clear', shell = True)
		
		print '''
  Il blocco dei siti non graditi avviene immettendo una parola chiave
  che identifica il sito, per esempio: google . 
  Per volere limitare il blocco solo a www.google.com ma non a 
  www.google.it, si potrebbe restringere il campo immettendo un indirizzo
  nella sua interezza, per esempio: www.google.com
  
  Svuotare i dati dal proprio browser rende effettiva la nuova regola. 
'''
		address_name_target = raw_input("\n\n\033[1m Parola chiave o address-name,"
							" ['q' per tornare al menu iniziale]\033[0m >  ")
		
		if address_name_target == 'q' or address_name_target == 'Q':
			
			running = False
			
			main_menu(version)()
		
		description = raw_input("\n\n\033[1m descrizione del sito.\n\033[0m >  ")
		
		diz = shelve.open('%s/sites_block.db'% path,'c')
		
		if diz.has_key(address_name_target) is False:
			diz[address_name_target] = description
			
			check_call('iptables -A OUTPUT -p tcp -m string --string "%s" '
								'--algo kmp -j REJECT' % (key), shell = True)
			
			#start test:-----------------------
			#print ("check_call('iptables -A OUTPUT -p tcp -m string --string "
							#"'%s' --algo kmp -j REJECT'" % (key))
			#end test--------------------------
			
			confirm = ("\n\033[1m SOURCE: Regola di 'blocco IP' "
										"impostata nel firewall.\033[0m")
		else:
			confirm = ("\n\033[31;1m SOURCE: Questa regola di "
							"'blocco' risulta già impostata.\033[0m")
						
		print graphic_address_block
		
		for key,val in diz.items():
			print("\033[36m  [%s]      --     %s\033[0m" 
												% (str(key), str(val)) )
		print confirm
		
		diz.close()
		raw_input("\n\033[1m Premi invio per continuare:\033[0m")
		
		
################################################# DELETES IP BLOCK
def IP_delete(path):
	"""
	Delete rules previously set with IP_insert() function
	"""
	running = True
	
	while running:
		
		call('clear', shell = True)
		
		print '''
  La procedura per rimuovere le regole precedentemente sottoscritte av-
  viene similmente a quella della loro sottoscrizione, cioè immettendo
  la parola o address-name esattamente corrispondente.
  Per vedere quali regole sono già state sottoscritte, tornare al menu
  e usare l'opzione che visualizza la loro lista. 
'''

		address_name_target = raw_input("\n\n\033[1m Parola chiave o "
							"address-name, ['q' per terminare]\033[0m >  ")
		
		if address_name_target == 'q' or address_name_target == 'Q':
			running = False
			main_menu(version)()
		
		diz = shelve.open('%s/sites_block.db'% path,'c') 
		
		if diz.has_key(address_name_target):
			del diz[address_name_target]
			
			#start test:-----------------------
			#print ("check_call('iptables -D OUTPUT -p tcp -m string --string "
							#"'%s' --algo kmp -j REJECT'" % (key))
			#end test--------------------------
			
			check_call('iptables -D OUTPUT -p tcp -m string --string "%s" '
								'--algo kmp -j REJECT' % (key), shell = True)
			
			
			confirm = ("\n\033[1m Regola di 'blocco IP' "
									"cancellata nel firewall.\033[0m")
		else:
			confirm =  "\n\033[31;1m Regola inesistente\033[0m"
			
		print graphic_address_block
		
		for key,val in diz.items():
			print("\033[36m  [%s]      --     %s\033[0m" 
											% (str(key), str(val)) )
		print confirm
		
		diz.close()
		raw_input("\n\n\033[1m Premi invio per continuare:\033[0m")
		
		
####################################################### TCP/UDP rules

def door_connect(path):
	"""
	Generates new rules on the doors tcp/udp protocols
	"""
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
	doortarget = raw_input("\n\n\033[1m Numero porta da sottoscrivere "
								"nelle regole del firewall\n\033[0m >  ")
	
	if str.isdigit(doortarget) is False:
		sys.exit("\n\n\033[31;1mBad option, is not integer\033[0m")
			
	description = raw_input("\n\n\033[1m Descrizione del servizio di "
											"appartenenza\n\033[0m >  ")
	
	opt = raw_input("\n\n\033[1m Tipo di Protocollo connessione: "
					"\033[32;1m|tcp|\033[0m / \033[32;1m|udp|\033[0m / "
										"\033[32;1m|tcp/udp|\033[0m >  ")
	
	target = raw_input("\n\n\033[1m Regola da applicare "
					":\033[32;1m|1|\033[0m(drop) \033[32;1m|2|\033[0m(reject) "
							"\033[32;1m|3|\033[0m(accept):\033[0m > N°  ")
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
		
		diz = shelve.open('%s/doors_rules_TCP.db'% path,'c')

		if diz.has_key(doortarget) is False:
			pass
		
		else:
			rule = diz[doortarget]
			
			print ("\n\n\033[31;1m La porta TCP %s è già stata sottoscritta "
			"alla regola %s.\n Se si intende procedere verrà sovrascritta "
			"da quella nuova:  \033[0m" % (doortarget, rule[1]))
			
			answer = raw_input("\n\033[1m Procedere? |y|n|.\033[0m >  ")
			
			if answer == "y" or answer == "Y":
				#print ("check_call('regola %s -j %s')" % (doortarget, rule[1]))
				check_call('iptables -D TCP -p tcp -m multiport --dport %s -j %s' 
										% (doortarget, rule[1]), shell = True)
				del diz [doortarget]
				
			elif answer == "n" or answer == "N":
				diz.close()
				main_menu(version)()
				
			else:
				sys.exit("\n\n\033[31;1mBad option, invalid input\033[0m")
						
		diz[doortarget] = description,"%s" % target
		#print "check_call('..regola %s -j %s')" % (doortarget,target)
		check_call('iptables -A TCP -p tcp -m multiport --dport %s -j %s' 
										%(doortarget,target), shell = True) 
		print graphic_rules_TCP
		
		for key,val in diz.items():
			print("\033[36m  [%s]        --       %s\033[0m" 
												% (str(key), str(val)) )
			
		diz.close()
		print ("\n\033[1m |TCP|: Porta '%s' del Servizio '%s' è appesa alla "
		"regola '%s' nel firewall.\033[0m" %(doortarget,description,target))
		
		raw_input("\n\033[1m Premi invio per continuare:\033[0m")
		
		main_menu(version)()
		
		
##### |UDP| insert

	elif opt == "udp" or opt == "UDP":  
		
		diz = shelve.open('%s/doors_rules_UDP.db'% path,'c') 
		
		if diz.has_key(doortarget) is False:
			pass
		
		else:
			rule = diz[doortarget]
			
			print ("\n\n\033[31;1m La porta UDP %s è già stata sottoscritta "
					"alla regola %s.\n Se si intende procedere verrà "
					"sovrascritta da quella nuova:  \033[0m" 
					% (doortarget, rule[1]))
			
			answer = raw_input("\n\033[1m Procedere? |y|n|.\033[0m >  ")
			
			if answer == "y" or answer == "Y":
				#print "--dport %s -j %s" % (doortarget, rule[1]))
				check_call('iptables -D UDP -p udp -m multiport --dport '
							'%s -j %s' % (doortarget, rule[1]), shell = True)
				del diz [doortarget]
				
			elif answer == "n" or answer == "N":
				diz.close()
				main_menu(version)()
				
			else:
				sys.exit("\n\n\033[31;1mBad option, invalid input\033[0m")
				
		diz[doortarget] = description,"%s" % target
		#print "check_call('--dport %s -j %s" % (doortarget,target)
		check_call('iptables -A UDP -p udp -m multiport --dport %s -j %s' 
										%(doortarget,target), shell = True) 
		print graphic_rules_UDP
		
		for key,val in diz.items():
			print("\033[36m  [%s]        --       %s\033[0m" 
												% (str(key), str(val)) )
		diz.close()
		
		print ("\n\033[1m |UDP|: Porta '%s' del Servizio '%s' è appesa "
									"alla regola '%s' nel firewall.\033[0m" 
										%(doortarget,description,target))
		
		raw_input("\n\033[1m Premi invio per continuare:\033[0m")
		
		main_menu(version)()
		
		
##### |TCP/UDP| insert

	elif opt == "tcp/udp" or opt == "TCP/UDP":			
		diz1 = shelve.open('%s/doors_rules_TCP.db'% path,'c')
		diz2 = shelve.open('%s/doors_rules_UDP.db'% path,'c') 
		
		if diz1.has_key(doortarget) is False:
			EXEC1 = '1'
			
		else:
			ruleTCP = diz1[doortarget]
			print ("\n\n\033[31;1m La porta TCP %s è già stata sottoscritta "
			"alla regola %s.\n Se si intende procedere verrà sovrascritta "
			"da quella nuova:  \033[0m" % (doortarget, ruleTCP[1]))
			
			answer = raw_input("\n\033[1m Procedere? |y|n|.\033[0m >  ")
			
			if answer == "y" or answer == "Y":
				#print "check_call(--dport %s -j %s)" % (doortarget, ruleTCP[1])
				
				check_call('iptables -D TCP -p tcp -m multiport --dport '
						'%s -j %s' % (doortarget, ruleTCP[1]), shell = True)
				
				del diz1 [doortarget]
				EXEC1 = '1'
				
			elif answer == "n" or answer == "N":
				EXEC1 = '0'
				
			else:
				sys.exit("\n\n\033[31;1mBad option, invalid input\033[0m")
				
		if EXEC1 == '1':
			diz1[doortarget] = description,"%s" % target
			#print "check_call(--dport %s -j %s)" % (doortarget,target)
			check_call('iptables -A TCP -p tcp -m multiport --dport '
							'%s -j %s' %(doortarget,target), shell = True)
			
			addTCP =  ("\n\033[1m |TCP|: Porta '%s' del Servizio '%s' è "
							"appesa alla regola '%s' nel firewall.\033[0m" 
								%(doortarget,description,target))
		elif EXEC1 == '0':
			addTCP = ("\n\033[31;1m |TCP|: Regola esistente invariata "
								"(porta:%s servizio:%s regola:%s).\033[0m" 
								% (doortarget, ruleTCP[0], ruleTCP[1]))
			
#============================================================
				
		if diz2.has_key(doortarget) is False:
			EXEC2 = '1'
			
		else:
			ruleUDP = diz2[doortarget]
			
			print ("\n\n\033[31;1m La porta UDP %s è già stata sottoscritta "
					"alla regola %s.\n Se si intende procedere verrà "
					"sovrascritta da quella nuova:  \033[0m" 
					% (doortarget, ruleUDP[1]))
					
			answer = raw_input("\n\033[1m Procedere? |y|n|.\033[0m >  ")
			
			if answer == "y" or answer == "Y":
				#print "check_call(--dport %s -j %s)" % (doortarget, ruleUDP[1])
				check_call('iptables -D UDP -p udp -m multiport --dport '
							'%s -j %s' % (doortarget, ruleUDP[1]), 
							shell = True)
				
				del diz2 [doortarget]
				EXEC2 = '1'
				
			elif answer == "n" or answer == "N":
				EXEC2 = '0'
				
			else:
				sys.exit("\n\n\033[31;1mBad option, invalid input\033[0m")
				
		if EXEC2 == '1':
			diz2[doortarget] = description,"%s" % target
			
			#print "check_call(--dport %s -j %s)" % (doortarget,target)
			check_call('iptables -A UDP -p udp -m multiport '
						'--dport %s -j %s' %(doortarget,target), shell = True)
			
			addUDP = ("\n\033[1m |UDP|: Porta '%s' del Servizio '%s' è "
						"appesa alla regola '%s' nel firewall.\033[0m" 
						%(doortarget,description,target))
						
		elif EXEC2 == '0':
			addUDP = ("\n\033[31;1m |UDP|: Regola esistente invariata "
						"(porta:%s servizio:%s regola:%s).\033[0m" 
						% (doortarget, ruleUDP[0], ruleUDP[1]))
		
				
		print graphic_rules_TCP
		for key,val in diz1.items():
			print("\033[36m  [%s]        --       %s\033[0m" 
					% (str(key), str(val)) )
			
		print graphic_rules_UDP
		for key,val in diz2.items():
			print("\033[36m  [%s]        --       %s\033[0m" 
					% (str(key), str(val)) )
			
		print addTCP
		print addUDP
		diz1.close()
		diz2.close()
		raw_input("\n\033[1m Premi invio per continuare:\033[0m")
		main_menu(version)()
		
##### end TCP insert				
	else:
		sys.exit("\n\n\033[31;1mBad option, invalid protocol (tcp? udp?)\033[0m")
		
		
		
#################################################### DELETES TCP/UDP rules

def door_delete(path):
	"""
	Deleting set previously rules on the doors tcp/udp protocols
	"""
	
	call('clear', shell = True)
	
	print '''\n
  \033[31;1mCANCELLAZIONE REGOLE SUI PROTOCOLLI TCP/UDP\033[0m
  
  La procedura per rimuovere le regole precedentemente sottoscritte av-
  viene similmente a quella della loro sottoscrizione, cioè immettendo
  il numero della porta TCP o UDP che sottointende la regola da eliminare.
  Per vedere quali regole sono già state sottoscritte, tornare al menu
  e usare l'opzione che visualizza la loro lista.
'''
	doortarget = raw_input("\n\n\033[1m Numero porta da cancellare dalle "
										"regole del firewall\n\033[0m >  ")
	
	opt = raw_input("\n\n\033[1m Tipo di Protocollo connessione: "
					"\033[32;1m|tcp|\033[0m / \033[32;1m|udp|\033[0m / "
					"\033[32;1m|tcp/udp|\033[0m >  ")
	
##### |TCP| delete

	if opt == "tcp" or opt == "TCP": 
		
		diz = shelve.open('%s/doors_rules_TCP.db'% path,'c') 
		
		if diz.has_key(doortarget) is True:
			pass
		
		else:
			print "\n\033[31;1m |TCP|: regola inesistente nel firewall\033[0m"
			raw_input("\n\n\033[1m\n Premi invio per tornare al menu "
						"iniziale:\033[0m")
			diz.close()
			main_menu(version)()
			
		rule = diz[doortarget]
		check_call('iptables -D TCP -p tcp -m multiport --dport %s -j %s' 
										%(doortarget,rule[1]), shell = True)
		#print "check_call(--dport %s -j %s)" %(doortarget,rule[1])
		
		del diz[doortarget]
		
		delTCP = ("\n\033[1m |TCP|: (Porta:'%s', Servizio:'%s', Target:'%s') "
							"Regola cancellata nel firewall.\033[0m" 
							% (doortarget, rule[0], rule[1]))
		
		print graphic_rules_TCP
		
		for key,val in diz.items():
			print("\033[36m  [%s]        --       %s\033[0m" 
								% (str(key), str(val)) )
		diz.close()
		
		print delTCP
		raw_input("\n\n\033[1m Premi invio per continuare:\033[0m")
		
		main_menu(version)()
		
##### |UDP| delete		
		
	elif opt == "udp" or opt == "UDP":  
		
		diz = shelve.open('%s/doors_rules_UDP.db'% path,'c')  
		
		if diz.has_key(doortarget) is True:
			pass
		
		else:
			print "\n\033[31;1m |UDP|: regola inesistente nel firewall\033[0m"
			raw_input("\n\n\033[1m\n Premi invio per tornare al menu "
						"iniziale:\033[0m")
			diz.close()
			main_menu(version)()
			
		rule = diz[doortarget]
		check_call('iptables -D UDP -p udp -m multiport --dport %s -j %s' 
									%(doortarget,rule[1]), shell = True)
		#print "check_call(--dport %s -j %s)" %(doortarget,rule[1])
		
		del diz[doortarget]
		
		delUDP = ("\n\033[1m |UDP|: (Porta:'%s', Servizio:'%s', Target:'%s') "
					"Regola cancellata nel firewall.\033[0m" 
					% (doortarget, rule[0], rule[1]))
		
		print graphic_rules_UDP
		
		for key,val in diz.items():
			print("\033[36m  [%s]        --       %s\033[0m" 
					% (str(key), str(val)) )
			
		diz.close()
		
		print delUDP
		raw_input("\n\n\033[1m Premi invio per continuare:\033[0m")
		
		main_menu(version)()
		
		
##### |TCP/UDP| delete
		
	elif opt == "tcp/udp" or opt == "TCP/UDP":  
		diz1 = shelve.open('%s/doors_rules_TCP.db'% path,'c')
		diz2 = shelve.open('%s/doors_rules_UDP.db'% path,'c')
						
		if diz1.has_key(doortarget) is True:
			
			ruleTCP = diz1[doortarget]
			
			delTCP = ("\n\033[1m |TCP|: (Porta:'%s', Servizio:'%s', "
						"Target:'%s') Regola cancellata nel firewall.\033[0m" 
						% (doortarget, ruleTCP[0], ruleTCP[1]))
			
			check_call('iptables -D TCP -p tcp -m multiport --dport %s -j %s' 
						%(doortarget,ruleTCP[1]), shell = True)
			#print "check_call(--dport %s -j %s)" %(doortarget,ruleTCP[1])
			del diz1[doortarget]
			
		else:
			delTCP = "\n\033[31;1m |TCP|: regola inesistente nel firewall\033[0m"
			
		if diz2.has_key(doortarget) is True:
			
			ruleUDP = diz2[doortarget]
			
			delUDP = ("\n\033[1m |UDP|: (Porta:'%s', Servizio:'%s', "
						"Target:'%s') Regola cancellata nel firewall.\033[0m" 
						% (doortarget, ruleUDP[0], ruleUDP[1]))
			
			check_call('iptables -D UDP -p udp -m multiport --dport %s -j %s' 
						%(doortarget,ruleUDP[1]), shell = True)
			#print "check_call(--dport %s -j %s)" %(doortarget,ruleUDP[1])
			
			del diz2[doortarget]
			
		else:
			delUDP = "\n\033[31;1m |UDP|: regola inesistente nel firewall\033[0m"
						
		print graphic_rules_TCP
		
		for key,val in diz1.items():
			print("\033[36m  [%s]        --       %s\033[0m" 
							% (str(key), str(val)) )
			
		print graphic_rules_UDP
		
		for key,val in diz2.items():
			print("\033[36m  [%s]        --       %s\033[0m" 
							% (str(key), str(val)) )		
		print delTCP
		print delUDP
		
		diz1.close()
		diz2.close()
		
		raw_input("\n\n\033[1m\n Premi invio per tornare al menu iniziale:\033[0m")
		
		main_menu(version)()
		
		
		
##### |TCP/UDP| err delete

	else:
		sys.exit("\n\n\033[31;1mBad option, invalid protocol (tcp? "
												"udp? tcp/udp?)\033[0m")
		
		
		
###############################################  REVIEWs IP BLOCK rules

def IP_review(path):
	"""
	Shows list with all block web sites
	"""
	
	call('clear', shell = True)
	
	diz = shelve.open('%s/sites_block.db'% path,'c') 
	
	print '''\033[1m   LISTA SITI WEB BLOCCATI \033[0m \033[34;1m
  ------------------------------------------------     
  KEY WORD:                         DESCRIPTION:
  ------------------------------------------------\033[0m'''
	for key,val in diz.items():
		print("\033[36m  [%s]      --     %s\033[0m" % (str(key), str(val)) )
	diz.close()
	
	raw_input('\033[34;1mPremi invio per continuare\033[0m')
	
	main_menu(version)()
	
	
	
######################################################  REVIEW TCP/UDP Rrules

def doors_review(path):
	"""
	Shows list with all tcp/udp rules
	"""
	call('clear', shell = True)
	
	diz = shelve.open('%s/doors_rules_TCP.db'% path,'c') 
	
	print '''\033[1m   LISTA REGOLE PORTE TCP/UDP \033[0m\033[34;1m

                 lista regole attive:
  ------------------------------------------------     
  TCP PORT:                NAME:     TARGETS:
  ------------------------------------------------\033[0m'''
  
	for key,val in diz.items():
		print("\033[36m  [%s]        --       %s\033[0m" 
						% (str(key), str(val)) )
	diz.close()
		
	diz = shelve.open('%s/doors_rules_UDP.db'% path,'c') 
	
	print '''\033[34;1m
  ------------------------------------------------     
  UDP PORT:                NAME:     TARGETS:
  ------------------------------------------------\033[0m'''
  
	for key,val in diz.items():
		print("\033[36m  [%s]        --       %s\033[0m" 
						% (str(key), str(val)) )
	diz.close()
	
	raw_input('\033[34;1mPremi invio per tornare al menu..\033[0m')
	
	main_menu(version)()
	
	
	
################################################################ STATUS

def status():
	"""
	Shows the formatted output of the command > iptables -nvL
	"""
	print "\033[34;1m===================================================\033[0m"
	print "\033[36m"
	check_call('iptables -nvL', shell=True)
	print ""
	print "\033[34;1m===================================================\033[0m"
	sys.exit()
	
	
	
######################################################  LOADs PROVA FUOCO

def load_all(path):
	"""
	Here are applied to all settings during startup the OS 
	(block sites, tcp and udp rules)
	"""
	
	################ applies block sites rules
	
	diz = shelve.open('%s/sites_block.db'% path,'c') 
	
	if len(diz) <= 0:
		# nessuna regola di blocco siti web impostata 
		# (No rule to block incoming set)
		diz.close()
		
	else:
		# "Attivo blocco IP [in] personale"
		for key in diz.keys():
			check_call('iptables -A OUTPUT -p tcp -m string --string "%s" '
								'--algo kmp -j REJECT' % (key), shell = True)
			#print "check_call(iptables -I INPUT -s %s -j DROP " % key
			
		diz.close()
		
	################ applies tcp rules
	
	diz = shelve.open('%s/doors_rules_TCP.db'% path,'c') 
	
	if len(diz) <= 0:
		# Nessuna regola TCP impostata"
		diz.close()
		
	else:
		# Attivo apertura connessione TCP personale
		val = diz.values()
		tupla = val[0]
		
		for key in diz.keys():
			check_call('iptables -A TCP -p tcp --dport %s -j %s' 
							%(key, tupla[1]), shell = True)
			#print "check_call(--dport %s -j %s" %(key, tupla[1])
			
		diz.close()
		
	################ applies udp rules
	
	diz = shelve.open('%s/doors_rules_UDP.db'% path,'c') 
	
	if len(diz) <= 0:
		# Nessuna regola UDP impostata"
		diz.close()
		sys.exit()
		
	else:
		# Attivo apertura connesione UDP personale
		val = diz.values()
		tupla = val[0]
		
		for key in diz.keys():
			check_call('iptables -A UDP -p udp --dport %s -j %s' 
							%(key, tupla[1]), shell = True)
			#print "check_call(--dport %s -j %s" %(key, tupla[1])
			
		diz.close()
		
		sys.exit()
