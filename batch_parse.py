import os
import sys
import time
import traceback
from luxuryParser import do_evrytin

#Unix-like functions
pwd = os.getcwd
cd = lambda x: os.chdir(x)
ls = lambda : os.listdir(pwd())

def current_time():
        return str(time.localtime()[3]).zfill(2)+":"+str(time.localtime()[4]).zfill(2)

def current_date():
		return "-".join(map(str,time.localtime()[:3]))

def move_to_load(f_name,dest="to_load"):
	# Mover los archivos a una subcarpeta
	print "Moving",f_name
	q = os.system("mv "+f_name+".* "+dest)

if __name__ == '__main__':
	archs_here = ls()
	pdfs_here = set()
	txt_csv_here = set()
	for f in archs_here:
		if f.endswith(".pdf"):
			pdfs_here.add(f[:f.find(".pdf")])
	
		if f.endswith(".txt.csv"):
			txt_csv_here.add(f[:f.find(".txt.csv")])
	
	pdfs_not_done = list(pdfs_here - txt_csv_here)
	pdfs_not_done.sort()
	
	error_name = current_date()+"_"+current_time().replace(":","-")+".error_log"
	error_log = open(error_name,"w")

	t_i = time.time()
	t_this = t_i
	print "Starting at", current_time()
	error_log.write("Started at: "+current_time()+"\n")
	for f in pdfs_not_done:
		filename = f+".pdf"
		print "Processing",filename,"..."
		error_log.write("Processing "+filename+" at "+current_time()+"\n")
		try:
			(l_luxParse,l_cleaner,l_tot) = do_evrytin(filename)
			move_to_load(f)
			time_passed_here = int(time.time()-t_this)
			time_total = int(time.time()-t_i)
			error_log.write(current_time()+" - " + filename + " done in "+str(time_passed_here)+"\n")
			error_log.write(" "+str(l_luxParse)+" parser | "+ str(l_cleaner) + " cleaner | "+str(l_tot)+ " totales\n")
			print "  ",filename,"done in" ,time_passed_here,"seconds","| Total time elapsed:",time_total,"[s]"
			t_this = time.time()
		except Exception:
			(type_, value_, tb) = sys.exc_info()
			error_log.write(current_time() + " - " + repr(value_)+"\n")
			for line in traceback.format_exception(type_, value_, tb):
				print line
				error_log.write(" "+line)
			error_log.write("-"*15+"\n")
		print "-"*15

	

