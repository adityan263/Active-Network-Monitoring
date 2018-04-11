import socket, cProfile
import sys
from decode import *
from gui import *
import os
import threading
import time
from globalvars import thelist
import globalvars
from pcap import Pcap
from Active import *


finish = threading.Event()
saving = threading.Event()

def fillin():
    pcap = Pcap("capture.pcap")
    if os.geteuid() != 0:
        print("Root privileges needed")
        finish.set()
    i = 1
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while not finish.is_set():
        raw_data, addr = conn.recvfrom(65535)
        try:
            ethernet = Ethernet(raw_data)
            if ethernet.proto == 8:
                #IPV4
                ipv4 = IPv4(ethernet.data)
                if ipv4.proto == 1:
                    #Icmp
                    icmp = ICMP(ipv4.data)
                    print("ICMP")
                elif ipv4.proto == 6:
                    #Tcp
                    tcp = TCP(ipv4.data)
                elif ipv4.proto == 17:
                    #Udp
                    upd = UDP(ipv4.data)
                elif ipv4.proto == 88:
                    #Igmp
                    igmp = IGMP(ipv4.data)
            elif ethernet.proto == 1544:
		#Arp
                arp = ARP(ethernet.data)
            elif ethernet.proto == 13576:
                #Rarp
                rarp = RARP(ethernet.data)
            elif ethernet.proto == 56710:
                #Ipv6
                ipv6 = IPv6(ethernet.data)
                pass
        except:
            print(raw_data)
            print(ethernet.proto)
            print(ethernet.data)
            print(len(ethernet.data))
            print("not enough bytes")
            finish.set()
        thelist.append((i, ethernet.dest_mac_addr,
            ethernet.src_mac_addr,ethernet.proto, raw_data))
        if saving.is_set():
            pcap.write(raw_data)
        i += 1
    pcap.close()

def main():
    tk = Tk()
    tk.title("Active Network Monitoring")
    tk.geometry("200x120")
    tk.protocol("WM_DELETE_WINDOW",lambda:finish.is_set())
    def close_window():
        tk.destroy()
        exit()
    options = Frame()
    options.pack(anchor=CENTER)
    choice = IntVar()
    button1 = Button(options,text="Send Packets", command=lambda: choice.set(1))
    button2 = Button(options,text="Read Packets", command=lambda: choice.set(2))
    button3 = Button(options,text="Quit", fg="red",command=close_window)
    button1.pack()
    button2.pack()
    button3.pack()
    
    button1.wait_variable(choice)
    options.destroy()

    if(choice.get() == 1):
        options = Frame()
        options.pack()
        button1 = Button(options,text="TCP", command=lambda: choice.set(0))
        button2 = Button(options,text="UDP", command=lambda: choice.set(1))
        button3 = Button(options,text="ICMP",command=lambda: choice.set(2))
        button1.pack(side=TOP)
        button2.pack(side=TOP)
        button3.pack(side=BOTTOM)

        button1.wait_variable(choice)
        options.destroy()


	#SENDING TCP PACKET
        if(choice.get() == 0):
           tcpwindow = Frame()
           tcpwindow.pack()	
           Label(tcpwindow, text="Enter Destination, Source Port, Destination Port", bg='black', fg='white', font='none 12 bold').grid(row = 0, column=0,sticky=W)
           destination = Entry(tcpwindow, width=20, bg='white')
           destination.grid(row = 1, column = 0, sticky = W)
           sport = Entry(tcpwindow, width=20, bg='white')
           sport.grid(row = 1, column = 1, sticky = W)
           dport = Entry(tcpwindow, width=20, bg='white')
           dport.grid(row = 1, column = 2, sticky = W)

           output = Text(tcpwindow, width=75, height=5, wrap=WORD, background='white')
           output.grid(row=4, column = 0, sticky = W)

           def click():
               d = destination.get()
               sp = int(sport.get())
               dp = int(dport.get())
               packet = TCPpacket(d,sp,dp)
               output.insert(END, packet.summary()+'\n')
#               tcpwindow.destroy()
#               tk.destroy()
#               exit()
           buttons = Button(tcpwindow, text="submit", width=6, command=click).grid(row=2,column=0,sticky=W)
           tcpwindow.mainloop()


	#SENDING UDP PACKET
        if(choice.get() == 1):
           udpwindow = Frame()
           udpwindow.pack()
           Label(udpwindow, text="Enter Destination, Source Port, Destination Port", bg='black', fg='white', font='none 12 bold').grid(row = 0, column=0,sticky=W)
           destination = Entry(udpwindow, width=20, bg='white')
           destination.grid(row = 1, column = 0, sticky = W)
           sport = Entry(udpwindow, width=20, bg='white')
           sport.grid(row = 1, column = 1, sticky = W)
           dport = Entry(udpwindow, width=20, bg='white')
           dport.grid(row = 1, column = 2, sticky = W)
           def click():
               d = destination.get()
               sp = sport.get()
               dp = dport.get()
               print(d,sp,dp)
               udpwindow.destroy()
               tk.destroy()
               exit()
           buttons = Button(udpwindow, text="submit", width=6, command=click).grid(row=2,column=0,sticky=W)
           udpwindow.mainloop()

	#SENDING ICMP PACKETS
        if(choice.get() == 2):
           print("IN")
           icmpwindow = Frame()
           icmpwindow.pack()
           Label(icmpwindow, text="Enter Source, Destination, Load, Time-to-live, Type ", bg='black', fg='white', font='none 12 bold').grid(row = 0, column=0,sticky=W)

           sourceentry = Entry(icmpwindow, width=20, bg='white')
           sourceentry.grid(row = 1, column = 0, sticky = W)

           destinationentry = Entry(icmpwindow, width=20, bg='white')
           destinationentry.grid(row = 1, column = 1, sticky = W)

           loadentry = Entry(icmpwindow, width=20, bg='white')
           loadentry.grid(row = 1, column = 2, sticky = W)

           ttlentry = Entry(icmpwindow, width=20, bg='white')
           ttlentry.grid(row = 1, column = 3, sticky = W)
	
           typeentry = Entry(icmpwindow, width=20, bg='white')
           typeentry.grid(row = 1, column = 4, sticky = W)


           def click():
               source = sourceentry.get()
               destination = destinationentry.get()
               load = loadentry.get()
               ttl = ttlentry.get()
               types = typeentry.get()
               print(source, destination, load, ttl, types)
               icmpwindow.destroy()
               tk.destroy()
               exit()
           buttons = Button(icmpwindow, text="submit", width=6, command=click).grid(row=2,column=0,sticky=W)
           icmpwindow.mainloop()


        options.destroy()

    elif(choice.get() == 2):
        tk.geometry("500x500")
        bttns = Frame()
        bttns.pack()
        paused = IntVar()
        mlb = MultiListbox(tk, (('No.', 5),('Destination', 20), ('Source', 20),
            ('Protocol', 10)))
        mlb.pack(expand=YES, fill=BOTH)
        i = 0
        button1 = Button(bttns,text="Start", fg="green", command=lambda: paused.set(0))
        button1.pack(side=LEFT)
        button2_text = StringVar()
        button2_text.set("Pause")
        button2 = Button(bttns,textvariable=button2_text, fg="yellow", command =
                lambda: paused.set(1))
        button2.pack(side=LEFT)
        button3 = Button(bttns,text="save", fg="blue",command=lambda:
                saving.clear() if saving.is_set() else saving.set())
        button3.pack(side=LEFT)
        button4 = Button(bttns,text="Quit", fg="red",command=lambda: finish.set())
        button4.pack(side=LEFT)
        text_frame = Frame()
        text_frame.pack()
        tex = Text(text_frame,width=454, height=50)
        tex.pack(side=BOTTOM)
        tk.update()
        t1 = threading.Thread(target=fillin)
        t1.start()
        while not finish.is_set():
            try:
                mlb.insert(END, (thelist[i][0], thelist[i][1], thelist[i][2], thelist[i][3]))
                tk.update()
                i += 1
                if paused.get():
                    button2.wait_variable(paused)
                    i = len(thelist)
            except:
                pass
            if globalvars.change:
                try:
                    tex.delete('1.0', END)
                except:
                    pass
                globalvars.change = 0
                tex.insert(INSERT, thelist[globalvars.sel_row][4])
                text_frame.update()
        t1.join()
    tk.destroy()

if __name__ == '__main__':
    #cProfile.run('main()')
    main()
