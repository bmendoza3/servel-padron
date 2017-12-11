# -*- coding: utf-8 -*-

import csv
import sys
sys.path.append('/u/a/2017/gaflores/transfer/dist-packages' ) #<---- ahi estan los modulos de servelParser
import json
#import googlemaps
import time
import traceback
import os
import subprocess
reload(sys)
sys.setdefaultencoding("utf-8")
import re
import codecs

from py_circs import circ_nombres, region_nums

#import sh

import ntpath

char_raro = '\x0c'

tres_esp = '   '

regex_manyEspacios = re.compile("\s[\s]+")
regex_whitelines = re.compile("(\s[\s]+|\t|\n)")

# ---------- Regex direccion ----
regex_pob = re.compile("(^|\s)(POB\s|POB\.|PB\s|PB\.|POBL\s|POBL\.|POBLACION)")
regex_pje = re.compile("(^|\s)(PJE\s|PJE\.|PSJE\s|PSJE\.|PSJ\s|PSJ\.|PJ\s|PJ\.|PASAJE)")
regex_calle = re.compile("(^|\s)(CL\s|CA\s)")
regex_avda = re.compile("(^|\s)(AV\s|AV\.|AVDA\s|AVDA\.|AVENIDA)")
regex_block = re.compile("(^|\s)(BLOC\s|BL\s|BL\.|BLOCK)")
regex_depto = re.compile("(^|\s)(DEPTO|DPTO\s|DPTO\.|DP\s|DEP\.|DEP\s|DEPARTAMENTO)")

def test():
	do_evrytin('El Tabo.pdf')

def path_filename(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)

def run(command):
	p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	return output


def do_evrytin(arch_pdf):
	nombre_archivo_ext = path_filename(arch_pdf)
	nombre_archivo = os.path.splitext(nombre_archivo_ext)[0]
	nombre_to_parse = nombre_archivo+".txt"
	X = run(" ".join(["pdftotext", "-layout", "'"+nombre_archivo_ext+"'", "'"+nombre_to_parse+"'"]))
	return parser(nombre_to_parse)

def len_cmp(x,y):
    if len(x) == len(y): return 0
    if len(x) < len(y): return -1
    return 1

def circ_in_line(posible_circ,Region,return_all=True):
    '''Busca en el string posible_circ el nombre de alguna circunscripcion
       perteneciente a la Region entregada -circunscripcion de py_circs-.
       Si se entrega return_all = False, solo entrega la que ocurre
       después en el string (la de más a la derecha), junto con el índice
       donde aparece.
       Ojo que las circunscripciones candidatas pueden ser distintas:
               "VALDIVIA DE PAINE            BUIN                 23 V"
       Tanto BUIN como PAINE son circunscripciones de la RM :/
    '''

    circs = []
    for circ in circ_nombres[Region]:
        if circ in posible_circ:
            circs.append(circ)

    if circs:
        circs.sort(cmp=len_cmp, reverse=True) # Nombres mas largos antes
        if return_all:
            return circs
        elif len(circs) == 1:
            return (circs[0], posible_circ.rfind(circs[0]))
        else:
            # 'UNICA S N HURTADO         RIO HURTADO (SAMO ALTO)      6\n'
            # Tanto "HURTADO" como "RIO HURTADO (SAMO ALTO)" son circunscripciones :c
            circ = "CIRCUNSCRIPTION_ERROR"
            i_circ = 300
            i_dcirc = 0
            for c in circs:
                i_c = posible_circ.rfind(c)
                i_dc = i_c + len(c)
                if i_dc > i_dcirc or (i_dc == i_dcirc and i_c < i_circ):
                    i_circ = i_c
                    i_dcirc = i_dc
                    circ = c
            return (circ, i_circ)
    return False

def bool_circInLine(posible_circ, Region):
	return not not circ_in_line(posible_circ, Region, False)

def is_circ(posible_circ, Region):
	return posible_circ in circ_nombres[Region]

regex_rut = re.compile("(((\d+.)?\d)?\d)?\d.\d{3}-(\d|K)")

def rut_in_line(line):
	return re.search(regex_rut,line) is not None

regex_mesa = re.compile("\d{1,3}(\s?\w|)$")
regex_mesaSpace = re.compile("\s\d{1,3}(\s?\w|)$")
regex_badMesa = re.compile("\d{1,3}[A-Z]$")

def mesa_in_line(line,space=False):
	if not space:
		return re.search(regex_mesa,line) is not None
	return re.search(regex_mesaSpace,line) is not None

def is_badMesa(line):
	return re.search(regex_badMesa,line) is not None

regex_pagina = re.compile("PAGINA\s[\d]+\sde\s[\d]+")
regex_provinciaHeader = re.compile("PROVINCIA[\s]+:[\s]+")

def is_header(line):
	if "PADRON ELECTORAL" in line:
		return True
	if re.search(regex_pagina, line) is not None:
		return True # PAGINA d+ de d+
	if re.search(regex_provinciaHeader, line) is not None:
		return True # PROVINCIA    : Maipo
	return False


regex_headerAttr = re.compile("NOMBRE[\s]+C.IDENTIDAD[\s]+SEXO[\s]+DOMICILIO\sELECTORAL")

def is_tableHeader(line):
	return re.search(regex_headerAttr, line) is not None


def is_dataLine(line):
	if is_header(line):
		return False
	if is_tableHeader(line):
		return False
	return True

def indexFirstChar(line):
	for i in range(len(line)):
		if line[i] != " ":
			return i
	return -1

def name_parser(nombre):
	palabras = nombre.split()
	if len(palabras) == 2:
		return (nombre,palabras[1],palabras[0],"")
	nombre = nombre.strip(' ')
	i_esp = nombre.find(' ')
	ap1 = nombre[:i_esp]
	i_esp2 = nombre.find(' ',i_esp+1)
	ap2 = nombre[i_esp+1:i_esp2]
	n_pila = nombre[max(i_esp2+1,i_esp):]

	Foreign_Starts = set(["J","K","C","P","T","X","F","Z","Y","G","H","Q"])
	def tipo_del(s):
		return (len(s) <= 3 and not any([s.startswith(c) for c in Foreign_Starts]) and\
				not s in ["RIO","MAR","SOL","REY"]) or s in ["SAN","SANTO","SANTA","SANT"]

	#apellidos frasales
	try:
		if len(ap1) <= 3 or len(ap2) <= 3:
			l_nombre = nombre.split()
			len_ap_1 = 1
			if tipo_del(l_nombre[0]):
				if not tipo_del(l_nombre[1]):
					ap1 = " ".join([l_nombre[0],l_nombre[1]])
					len_ap_1 +=1
				else:
					ap1 = " ".join([l_nombre[0],l_nombre[1],l_nombre[2]])
					len_ap_1 +=2
			else:
				ap_1 = l_nombre[0]

			i_ap_m = len_ap_1
			i_f = i_ap_m
			if tipo_del(l_nombre[i_ap_m]):
				if not tipo_del(l_nombre[i_ap_m+1]):
					ap2 = " ".join([l_nombre[i_ap_m],l_nombre[i_ap_m+1]])
					i_f = i_ap_m+1
				else:
					ap2 = " ".join([l_nombre[i_ap_m],l_nombre[i_ap_m+1],l_nombre[i_ap_m+2]])
					i_f = i_ap_m+2
			else:
				ap2 = l_nombre[i_ap_m]
			n_pila = " ".join(l_nombre[i_f+1:])
		if n_pila == "":
			n_pila = ap2
			ap2 = ""
		elif n_pila.startswith("DE "):
			#"CASTRO SOLIS DE OVANDO PAULINA ANDREA DE LA SANTISIMA TRINIDAD;15471103", independencia
			l_nombre = n_pila.split()
			ap2 += " " + l_nombre[0] + " " + l_nombre[1]
			n_pila = " ".join(l_nombre[2:])
	except IndexError:
		pass
	
	nombre = re.sub(regex_manyEspacios," ",nombre)
	return (nombre,n_pila, ap1, ap2)

def cleaner(arch):
	#print "hola c:"
	k=0
	j=0
	c=0
	a = open(arch,'r')
	r = open(arch+'.cln','w')
	vi_region_comuna = False
	vi_provincia = False
	for line in a:
		c+=1
		if not vi_region_comuna:
			if 'REGION' in line:
				i_pcoma = line.find(':')
				Region = line[i_pcoma+1: i_pcoma+37].strip()
			if 'COMUNA' in line:
				i_pcoma2 = line.find(':',i_pcoma+2)
				Comuna = line[i_pcoma2+1:i_pcoma2+46].strip()
				if tres_esp in Comuna:
					Comuna = Comuna[:Comuna.find(tres_esp)].rstrip()
				vi_region_comuna = True
		if not vi_provincia:
			if 'PROVINCIA' in line:
				i_pcoma = line.find(':')
				Provincia = line[i_pcoma+1: i_pcoma+37].strip()
				vi_provincia = True
		else:
			#print "Region",Region
			#print "line",line
			#if 'REPUBLICA' not in line and 'SERVICIO' not in line and 'PROVINCIA' not in line and circ_region_in_line(Region,line) and '-' in line and '.' in line:
			if is_dataLine(line):
				r.write(line)
				k+=1
			else:
				j+=1
			"""
			if circ_region_in_line(Region,line) and '-' in line and '.' in line:
				r.write(line)
				k+=1
			else: j+=1
			"""
	a.close()
	r.close()
	print ' Cleaner - lineas parseadas: '+str(k)+' de '+str(c)+' | No parseadas: '+str(j)
	return (k,c,Region,Comuna,Provincia)

def parser(arch):
	votantes,total_lineas,Region,Comuna,Provincia = cleaner(arch)
	N_Region = region_nums[Region]

	num = ('1','2','3','4','5','6','7','8','9','0')
	alf = ('Q','W','E','R','T','Y','U','I','O','P','A','S','D','F','G','H','J','K','L','Z','X','C','V','B','N','M')
	a = codecs.open(arch+'.cln','r','utf-8')
	r = open(arch+'.csv','w')
	datos = [dict() for x in range(votantes)]
	k=0 #contador de diccionarios con informacion
	#for line in a:
	line = a.readline()
	k_2 = 0

	nombre_desborde = ""
	
	while line not in ['',char_raro]:
		ask_for_line = True
		rut_problema = "99.876.681"	# DEBUGGING
		nombre_prob = "NOMBRE FALSO" # idem
		
		largo = len(line)
		line = line.replace('"', "'").replace("\t",tres_esp)

		# --------------- Viendo el problema del desborde de nombres
		# 	(arriba de CASTRO SOTO EMILIO OSVALDO   18.331.684-2; independencia)
		nombre = ""

		pals = line.strip().split()
		n_palabras = len(pals)
		i_primer_char = indexFirstChar(line)

		if n_palabras < 4 and i_primer_char < 25: # si hay pocas palabras y pocos espacios que
													 # la anteceden, se desbordó el nombre anterior

			nombre_desborde = " ".join(pals)

			new_oldname = datos[k-1]["Nombre"] + " "+ nombre_desborde
			datos[k-1]["Nombre"] = re.sub(regex_manyEspacios," ",new_oldname)

			new_surname = datos[k-1]["N_Pila"] + " "+ nombre_desborde
			datos[k-1]["N_Pila"] = re.sub(regex_manyEspacios," ",new_surname)

		elif 3 < i_primer_char < 25 and nombre_desborde != "":
			datos[k-1]["Nombre"] = datos[k-1]["Nombre"][:-len(nombre_desborde)]
			datos[k-1]["N_Pila"] = datos[k-1]["N_Pila"][:-len(nombre_desborde)]

			nombre += nombre_desborde.split()[0]

			datos[k-1]["Nombre"] += " "+ " ".join(nombre_desborde.split()[1:])
			datos[k-1]["N_Pila"] += " "+ " ".join(nombre_desborde.split()[1:])
			datos[k-1]["Nombre"] = re.sub(regex_manyEspacios," ",datos[k-1]["Nombre"])
			datos[k-1]["N_Pila"] = re.sub(regex_manyEspacios," ",datos[k-1]["N_Pila"])
		else:
			nombre_desborde = ""		
					
		
		# --------------- endproblema
        
		if re.search(regex_rut,line) is None: #no hay un rut en esta linea (basura)
			k_2 += 1
			#print "badline"+str(k_2)">"+line+"<"
			line = a.readline()
			continue

	
		line = line.lstrip()

		#CLAUDIO ALBERTO               9.546.666-4   VAR      GALVARINO 89 VALDIVIA DE PAINE            BUIN                 23 V
		#				^i_3e					^i_guion     ^i_dir                         ^i_3ed  
		#siempre identificamos los campos separados por tres espacios ___

		#tres_esp: tres espacios
		i_3e = line.find(tres_esp)
		#nombre
		nombre += " "+line[:i_3e]
		i_guion = line.find('-',i_3e)
		#rut
		rut = line[i_3e+3:i_guion].strip()
		if (rut == rut_problema) or (nombre_prob in nombre): print "line", repr(line) #DEBUGGING

		if any([c.isalpha() for c in rut]): #metimos mas cosas al rut de lo necesario
			#"SCHWANER   FRAMER ARTURO ROLANDO                    151.410-5   VAR", Los Vilos
			rut = re.sub(regex_manyEspacios," ",rut)
			l_rut = rut.split()
			rut = l_rut[-1]
			add_nombre = " ".join(l_rut[:-1])
			nombre += " " + add_nombre
		#dv
		dv = line[i_guion+1]
		#sexo
		sexo = line[i_guion+5:i_guion+8]

		i_dir = i_guion+12
		i_3ed = line.find(tres_esp,i_dir)
		cola = line[i_3ed:-1]
		if (rut == rut_problema) or (nombre_prob in nombre): print "cola", repr(cola) #DEBUGGING
		#caso facil - cola:  "           BUIN                 23 V"
		#caso feo: - linea: CLAUDIO ALBERTO               9.546.666-4   VAR      GALVARINO 	
		#																			89 VALDIVIA
		#																				DE PAINE        
		#							     BUIN                 23 V
		# (direccion flotando en muchas lineas)
		#not_done=True
		if all([char==" " for char in cola]): #caso dificil
			if i_3ed == -1: 
				dir_old = line[i_dir:]
			else:
				dir_old = line[i_dir:i_3ed]

			datos[k-1]["Dir_Servel"] += " " + dir_old
			#direccion caso dificil
			direccion = ""
			n_whiles = 0
			while all([char==" " for char in cola]):
				n_whiles += 1
				line = a.readline()
				line = line.lstrip()
				i_3e2 = line.find(tres_esp)
				if (rut == rut_problema) or (nombre_prob in nombre): print "line", repr(line) #DEBUGGING
				direccion += " "+line[:i_3e2] # le pego los pedazos de la direccion flotando

				cola = line[i_3e2:]
				posible_circ = cola.strip()
				#si cola es string de espacios, posible_circ == ''
				if posible_circ == '': continue

				"""
				any_one = False #hay un nombre de circunscripcion en la nueva linea?
				for circ in circ_nombres[Region]:
					if circ in posible_circ:
						any_one = True
						break
				"""
				
				new_line = a.readline()
				try:
					is_there_circ = circ_in_line(posible_circ,Region,False) #puede ser tupla o False
				except TypeError:
					print "k",k
					print "posible_circ",repr(posible_circ)
					print "Region",repr(Region)
					break

				if (rut == rut_problema) or (nombre_prob in nombre): print "is_there_circ", is_there_circ #DEBUGGING

				if is_there_circ: #hay algo que parece circ
					if ('.' in new_line and '-' in new_line):
						#si hay circ (en esta linea) Y rut (en la SIGUIENTE LINEA), terminamos con esta linea
						(circ,i_circ) = is_there_circ

						direccion += " "+posible_circ[:i_circ].rstrip() #posible_circ actua como "cola"
						#new_cola = posible_circ[i_circ:].strip() 
						# circunscripcion caso dificil
						circunscripcion = circ
						#mesa caso dificil
						mesa = posible_circ[i_circ+len(circ)+1:].strip()
						#not_done = False <------
				else:
					direccion += " "+posible_circ[:-1].rstrip() # no era circunscripcion :c
					
				line = new_line
				"""
				new_line = a.readline().replace('"',"'")
				while not (mesa_in_line(new_line.rstrip(),True) and bool_circInLine(new_line, Region) ):
					n_whiles += 1
					direccion += " " + new_line.strip()
					new_line = a.readline().replace('"',"'")
				#new_line ahora tiene mesa y circ


				(circunscripcion,i_circ) = circ_in_line(new_line,Region,False)
				mesa = new_line[i_circ+len(circunscripcion)+1:].replace('\n','').strip()

				if n_whiles == 1:
					#si solo una linea es la dislocada, generalmente es 
					l_dir_old = dir_old.strip().split()
					datos[k-1]["Dir_Servel"] = datos[k-1]["Dir_Servel"][:-len(dir_old)] #le quito lo que le puse
					datos[k-1]["Dir_Servel"] += " " + l_dir_old[0]
					
					direccion = " ".join(l_dir_old[1:]) + " " + direccion
			
				break
				"""
				#
				""" --Debajo de "#si hay circ Y rut", si sigo con esta linea de desarrollo
				# Hint: las circunscripciones siempre estan en la misma linea que la mesa
				while (re.search(regex_mesa, new_line.rstrip()) is None):
					# Mientras la nueva linea no termine en algo en forma de mesa
					direccion += " " + new_line.strip()
					new_line = a.readline()
				#ahora termina en algo con forma de mesa
				i_circ = posible_circ.find(circ)
				direccion += " "+posible_circ[:i_circ].rstrip()
				#circunscripcion caso dificil
				circunscripcion = posible_circ[i_circ:i_circ+len(circ)]
				#mesa caso dificil
				mesa = posible_circ[i_circ+len(circ)+1:-1].strip()
				"""			
			
		else: #caso facil - not all([char==" " for char in cola])
			#direccion caso facil
			direccion = line[i_dir:i_3ed].strip()
			cola = line[i_3ed:].lstrip()

			if cola == "":
				new_line = a.readline().replace('"',"'")
				while not (mesa_in_line(new_line.rstrip(),True) and bool_circInLine(new_line, Region) ):
					direccion += " " + new_line.strip()
					new_line = a.readline().replace('"',"'")
				cola = new_line

			cola_strip = cola.rstrip()
			if mesa_in_line(cola_strip):
				is_there_circ = circ_in_line(cola,Region,False)
				#circunscripcion caso facil
				if is_there_circ:
					(circunscripcion,i_circ) = circ_in_line(cola,Region,False)
					"""
					# 'UNICA S N HURTADO         RIO HURTADO (SAMO ALTO)      6\n'
					# Tanto "HURTADO" como "RIO HURTADO (SAMO ALTO)" son circunscripciones :c
					i_pos_mesa = cola_strip.rfind(tres_esp) #procesando de der a izq
					posible_mesa = cola_strip[i_pos_mesa:]
					
					posible_circ = cola_strip[:i_pos_mesa].strip()
					if mesa_in_line(posible_mesa) and is_circ(posible_circ, Region):
						circunscripcion = posible_circ
						mesa = posible_mesa.strip()
					else:
					"""
					if i_circ > 0:
						direccion += " "+cola[:i_circ].rstrip()
					#mesa caso facil
					mesa = cola[i_circ+len(circunscripcion)+1:].replace('\n','').strip()
				else: #not is_there_circ
					#  es feo, pero voy a quitarle la ultima palabra a la direccion
					#  hasta ver si ahi esta la circunscripcion
					i_ult = 300
					dir_old = direccion
					while not circ_in_line(cola,Region,False) and i_ult!=-1:
						i_ult = direccion.rfind(" ")
						cola = direccion[i_ult:]+cola
						direccion = direccion[:i_ult]

					if i_ult != -1:
						(circunscripcion,i_circ) = circ_in_line(cola,Region,False)
						#mesa caso facil
						mesa = cola[i_circ+len(circunscripcion)+1:].replace('\n','').strip()
					else:	
						#no habia circ
						direccion = dir_old
						"""
						print "Sad :c"
						print " line",repr(line)
						print " cola",repr(cola)
						"""
						new_line = a.readline()
						while not mesa_in_line(new_line.strip()):
							direccion += " " + new_line.strip()
							new_line = a.readline()
						#ahora sí termina en mesa (=> tiene circ)
						new_line = new_line.rstrip()
						i_mesa = new_line.rfind(tres_esp)
						mesa = new_line[i_mesa:].strip()
						cola = new_line[:i_mesa]

						try:
							(circunscripcion,i_circ) = circ_in_line(cola,Region,False)
						except TypeError:
							print "Error caso facil"
							print "line -",repr(line)
							print "new_line -",repr(new_line)
							print "cola -",repr(cola)
							(type_, value_, tb) = sys.exc_info()
							for e_line in traceback.format_exception(type_, value_, tb):
								print e_line
							raise ValueError("Error de circunscripcion")
							break
						cola = cola[:i_circ].strip()
				
						direccion += " " + cola

			else: # not mesa_in_line(cola_strip)
				#   no termina en mesa, probablemente quedo en la linea de abajo
				direccion += " " + cola

				new_line = a.readline()
				while not mesa_in_line(new_line.strip(),True):
					direccion += " " + new_line.strip()
					new_line = a.readline()
				#ahora sí termina en mesa
				new_line = new_line.rstrip()
				i_mesa = new_line.rfind(tres_esp)
				mesa = new_line[i_mesa:].strip()

				# Hint: las circunscripciones siempre estan en la misma linea que la mesa
				cola = new_line[:i_mesa]
				try:
					(circunscripcion,i_circ) = circ_in_line(cola,Region,False)
				except TypeError:
					print "line -",repr(line)
					print "new_line -",repr(new_line)
					print "cola -",repr(cola)
					break
				cola = cola[:i_circ].strip()
				
				direccion += " " + cola
							

			if ask_for_line:
				line = a.readline()
		
		#normalizando (algunas) direcciones)
		direccion = direccion.replace(".",". ")
		direccion = direccion.replace('"',"'")
		direccion = re.sub(regex_pob," POB. ",direccion)
		direccion = re.sub(regex_avda," AV. ",direccion)
		direccion = re.sub(regex_calle," CL. ",direccion)
		direccion = re.sub(regex_pje," PJE. ",direccion)
		direccion = re.sub(regex_depto," DPTO. ",direccion)
		direccion = re.sub(regex_block," BLOCK ",direccion)

		direccion = re.sub(regex_manyEspacios," ", direccion)
		try:
			datos[k-1]["Dir_Servel"] = re.sub(regex_whitelines," ",datos[k-1]["Dir_Servel"])
		except KeyError:
			pass

		#normalizando mesa
		if is_badMesa(mesa):
			char = mesa[-1]
			mesa = mesa[:-1] + " " + char

		if (rut == rut_problema) or (nombre_prob in nombre): print "mesa", repr(mesa) #DEBUGGING
		if (rut == rut_problema) or (nombre_prob in nombre): print "direccion", repr(direccion) #DEBUGGING


		"""
		for i in range(largo):
			if line[i]==' ' and line[i+1]==' ' and line[i+2]==' ':
				nombre =line[:i]
				for j in range(i+15,largo):
					if line[j] in num:
						for n in range(j,j+10):
							if line[n]=='-':
								rut = line[j:n+2] #n = sin incluir ni guion ni digito verificador
								dv = line[n+1]
								sexo = line[n+5:n+8]
								for m in range(n+13,largo):
									if line[m]==' ' and line[m+1]==' ' and line[m+2]==' ':
										direccion = line[n+13:m]
										for p in range(m+3,largo):
											if line[p] in alf:
												circunscripcion = line[p:p+45]
												mesa = line[p+45:-1]
												break
										break
								break
							else: continue
						break 
					else: continue
				break
			else: continue
		"""
		nombre = re.sub(regex_manyEspacios," ",nombre).strip()

		#parseando apellido1, apellido2, nombres (usa hartos supuestos)
		(nombre, n_pila, ap1, ap2) = name_parser(nombre)
		
		try:
			nombre = nombre.decode('utf-8')
			ap1 = ap1.decode('utf-8')
			ap2 = ap2.decode('utf-8')
			n_pila = n_pila.decode('utf-8')
			rut = rut.decode('utf-8')
			circunscripcion = circunscripcion.decode('utf-8')
			mesa = mesa.decode('utf-8')
		except Exception:
			print "qué pasó???"
			break

		try:
			direccion = direccion.decode('utf-8')
		except UnicodeDecodeError:
			print "Unicode error :c"
			print "direccion -",repr(direccion)
			print "line -",repr(line)
			print "tipos: dir",type(direccion)," | line",type(line)
			raise UnicodeDecodeError("Unicode error :c \n| line -"+repr(line))
		
		datos[k]= { 'Nombre':nombre,
					'Apellido_P':ap1,
					'Apellido_M':ap2,
					'N_Pila':n_pila,
					'Rut':rut.replace('.',''),
					'DV':dv,
					'Circuns':circunscripcion.strip(' '),
					'Mesa':mesa.strip(' '),
					'Sexo':sexo,
					'Dir_Servel':direccion.strip(' '),
					'Region':N_Region,
					'Provincia':Provincia,
					'Comuna':Comuna
		}

		#???????????????????????
		if datos[k].keys() == datos[k].values() == []:
			del datos[k]
		k+=1
	
	
	estrin = 'Nombre;Rut;DV;Circuns;Mesa;Sexo;Dir_Servel;Region;Provincia;Comuna;Apellido_P;Apellido_M;N_Pila\n'
	keys = estrin[:-1].split(";")
	r.write(estrin)
	#print "????????????????????",("Nombre" in datos[4].keys())
	for i in range(k):
		estrin2 = ""
		#For testing only
		for data_attribute in keys:
			#estrin2 += str(datos[i][data_attribute])+";"
			
			try:
				estrin2 += str(datos[i][data_attribute])+";"
			except KeyError:
				#print "i",":ooo"
				break
			
		r.write(estrin2[:-1]+"\n")
	a.close()
	r.close()
	print 'Done -',k,"Entradas creadas |",k_2,"lineas malas"
	return (k,votantes,total_lineas)

if __name__  == '__main__':
	n_args = len(sys.argv)
	if n_args > 1:
		if not any([s[0] == '-' for s in sys.argv[1:]]): #no hay flag
			for comuna in sys.argv[1:]:
				parser(comuna+".txt")
		elif sys.argv[1][0] != "-": #hay flag, pero no es el primer parametro
			print " Error de sintaxis: La opcion debe ser el primer parámetro"
		else:
			flag = sys.argv[1]
			if any([s[0] == '-' for s in sys.argv[2:]]):
				" Error de sintaxis: Especifique sólo un parámetro"
			param = flag[1:]
			if param.lower() == "p":
				for comuna in sys.argv[2:]:
					if comuna.endswith(".txt"):
						parser(comuna)
					else:
						parser(comuna+".txt")
			elif param.lower() in ["d","c","a"]:
				print " Prefiera usar batch_parse.py"
				for comuna in sys.argv[2:]:
					if comuna.endswith(".pdf"):
						do_evrytin(comuna)
					else:
						do_evrytin(comuna+".pdf")
			else:
				print " Parámetro desconocido"
	else:
		print "Ctrl+C para salir"
		while True:
			try:
				p = parser(raw_input("Ingrese nombre comuna [sin .txt]> ")+".txt")
			except ValueError:
				break
			except Exception:
				continue
