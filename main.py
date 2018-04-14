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
    dictionary = {8:"ipv4",1544:"arp",13576:"rarp",56710:"ipv6"}
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
                thelist.append((i, ipv4.src_ip_addr,
                    ipv4.target_ip_addr,dictionary[ethernet.proto], raw_data))
            elif ethernet.proto == 1544:
		#Arp
                arp = ARP(ethernet.data)
                thelist.append((i, "-",
                    "-",dictionary[ethernet.proto], raw_data))
            elif ethernet.proto == 13576:
                #Rarp
                rarp = RARP(ethernet.data)
                thelist.append((i, "-",
                    "-",dictionary[ethernet.proto], raw_data))
            elif ethernet.proto == 56710:
                #Ipv6
                ipv6 = IPv6(ethernet.data)
                thelist.append((i, ipv6.src_ip_addr,
                    ipv6.dest_ip_addr,dictionary[ethernet.proto], raw_data))
                pass
        except:
            print(raw_data)
            print(ethernet.proto)
            print(ethernet.data)
            print(len(ethernet.data))
            print("not enough bytes")
            finish.set()
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

    #SEND PACKETS
    if(choice.get() == 1):
        options = Frame()
        tk.geometry("1200x800")
        options.pack()
        Label(options, text="Choose Packet-Protocol Format",font='none 12 bold').pack()
        button1 = Button(options,text="TCP", width = 25, command=lambda: choice.set(0))
        button2 = Button(options,text="UDP", width = 25, command=lambda: choice.set(1))
        button3 = Button(options,text="ICMP",width = 25, command=lambda: choice.set(2))
        button4 = Button(options,text="ARP",width = 25, command=lambda: choice.set(3))
        button4.pack(fill=X, side=TOP)
        button3.pack(fill=X, side=TOP)
        button1.pack(fill=X, side=TOP)
        button2.pack(fill=X, side=TOP)

        def click_back():
            options.destroy()
            tk.destroy()
            main()

        Button(options, text="BACK", width=25, command=click_back).pack(fill=X, side=TOP)
        def click_quit():
            options.destroy()
            tk.destroy()
            exit()
        Button(options, text="QUIT", width=25, command=click_quit).pack(fill=X, side=BOTTOM)
        button1.wait_variable(choice)
        options.destroy()

	#SENDING TCP PACKET
        if(choice.get() == 0):
           tcpwindow = Frame()
           tcpwindow.pack()
           Label(tcpwindow, text="Customize Packet Contents :", bg='black', fg='white', font='none 12 bold').grid(row=0, column=0, sticky=W)
           Label(tcpwindow, text="Destination", bg='black', fg='white', font='none 12 bold').grid(row=1, column=0, sticky=W)
           destination = Entry(tcpwindow, width=20, bg='white')
           destination.grid(row = 1, column = 1, sticky = W)
           Label(tcpwindow, text="Source Port", bg='black', fg='white', font='none 12 bold').grid(row=2, column=0, sticky=W)
           sport = Entry(tcpwindow, width=20, bg='white')
           sport.grid(row = 2, column = 1, sticky = W)
           Label(tcpwindow, text="Destination Port", bg='black', fg='white', font='none 12 bold').grid(row=3, column=0, sticky=W)
           dport = Entry(tcpwindow, width=20, bg='white')
           dport.grid(row = 3, column = 1, sticky = W)

           output = Listbox(tcpwindow, width=60)
           output.grid(row=5, column = 0, sticky = W)

           def click():
               d = destination.get()
               if not valid_ip(d):
                   tkMessageBox.showerror("Error","Enter valid Destination IP")
                   return
               sp = sport.get()
               if not valid_port(sp):
                   tkMessageBox.showerror("Error","Enter valid Source-Port Number")
                   return
               dp = dport.get()
               if not valid_port(dp):
                   tkMessageBox.showerror("Error","Enter valid Destination-Port Number")
                   return
               packet = TCPpacket(d,int(sp),int(dp))
               output.insert(END, packet.summary()+'\n')
           buttons = Button(tcpwindow, text="Submit", width=6, command=click).grid(row=4,column=1,sticky=W)

           def click_quit():
               tcpwindow.destroy()
               tk.destroy()
               exit()
           Button(tcpwindow, text="QUIT", width=6, command=click_quit).grid(row=10,column=5,sticky=W)
           tcpwindow.mainloop()

	#SENDING UDP PACKET
        if(choice.get() == 1):
           udpwindow = Frame()
           udpwindow.pack()
           Label(udpwindow, text="Customize Packet Contents :", bg='black', fg='white', font='none 12 bold').grid(row=0, column=0, sticky=W)
           Label(udpwindow, text="Destination", bg='black', fg='white', font='none 12 bold').grid(row=1, column=0, sticky=W)
           destination = Entry(udpwindow, width=20, bg='white')
           destination.grid(row = 1, column = 1, sticky = W)
           Label(udpwindow, text="Source Port", bg='black', fg='white', font='none 12 bold').grid(row=2, column=0, sticky=W)
           sport = Entry(udpwindow, width=20, bg='white')
           sport.grid(row = 2, column = 1, sticky = W)
           Label(udpwindow, text="Destination Port", bg='black', fg='white', font='none 12 bold').grid(row=3, column=0, sticky=W)
           dport = Entry(udpwindow, width=20, bg='white')
           dport.grid(row = 3, column = 1, sticky = W)
           output = Listbox(udpwindow, width=60)
           output.grid(row=5, column = 0, sticky = W)
           def click():
               d = destination.get()
               if not valid_ip(d):
                   tkMessageBox.showerror("Error","Enter valid Destination IP")
                   return
               sp = sport.get()
               if not valid_port(sp):
                   tkMessageBox.showerror("Error","Enter valid Source-Port Number")
                   return
               dp = dport.get()
               if not valid_port(dp):
                   tkMessageBox.showerror("Error","Enter valid Destination-Port Number")
                   return
               packet = UDPpacket(d,int(sp),int(dp))
               output.insert(END, packet.summary()+'\n')
           buttons = Button(udpwindow, text="Submit", width=6, command=click).grid(row=4,column=1,sticky=W)
           
           def click_quit():
               udpwindow.destroy()
               tk.destroy()
               exit()
           Button(udpwindow, text="QUIT", width=6, command=click_quit).grid(row=10,column=5,sticky=W)
           udpwindow.mainloop()

	#SENDING ICMP PACKETS
        if(choice.get() == 2):
           icmpwindow = Frame()
           icmpwindow.pack()
           Label(icmpwindow, text="Customize Packet Contents :", bg='black', fg='white', font='none 12 bold').grid(row=0, column=0, sticky=W)
           Label(icmpwindow, text="Source", bg='black', fg='white', font='none 12 bold').grid(row=1, column=0, sticky=W)
           sourceentry = Entry(icmpwindow, width=20, bg='white')
           sourceentry.grid(row = 1, column = 1, sticky = W)
           Label(icmpwindow, text="Destination", bg='black', fg='white', font='none 12 bold').grid(row=2, column=0, sticky=W)
           destinationentry = Entry(icmpwindow, width=20, bg='white')
           destinationentry.grid(row = 2, column = 1, sticky = W)
           Label(icmpwindow, text="Raw Load", bg='black', fg='white', font='none 12 bold').grid(row=3, column=0, sticky=W)
           loadentry = Entry(icmpwindow, width=20, bg='white')
           loadentry.grid(row = 3, column = 1, sticky = W)
           Label(icmpwindow, text="Time-to-live", bg='black', fg='white', font='none 12 bold').grid(row=4, column=0, sticky=W)
           ttlentry = Entry(icmpwindow, width=20, bg='white')
           ttlentry.grid(row = 4, column = 1, sticky = W)
           Label(icmpwindow, text="Error Type", bg='black', fg='white', font='none 12 bold').grid(row=5, column=0, sticky=W)
           typeentry = Entry(icmpwindow, width=20, bg='white')
           typeentry.grid(row = 5, column = 1, sticky = W)
           output = Listbox(icmpwindow, width=60)
           output.grid(row=7, column = 0, sticky = W)

           def click():
               source = sourceentry.get()
               if not valid_ip(source):
                   tkMessageBox.showerror("Error","Enter valid Destination IP")
                   return
               destination = destinationentry.get()
               if not valid_ip(destination):
                   tkMessageBox.showerror("Error","Enter valid Destination IP")
                   return
               load = loadentry.get()
               ttl = ttlentry.get()
               if not ttl.isdigit():
                   return
               types = typeentry.get()
               if not types.isdigit():
                   return
               packet = ICMPpacket(source, destination, int(ttl), int(types), load)
               output.insert(END, packet.summary()+'\n')
           Button(icmpwindow, text="Submit", width=6, command=click).grid(row=6,column=1,sticky=W)

           def click_quit():
               icmpwindow.destroy()
               tk.destroy()
               exit()
           Button(icmpwindow, text="QUIT", width=6, command=click_quit).grid(row=10,column=5,sticky=W)
           icmpwindow.mainloop()

        options.destroy()

	#SENDING ARP packets
        if(choice.get() == 3):
           arpwindow = Frame()
           arpwindow.pack()
           Label(arpwindow, text="Customize Packet Contents :", bg='black', fg='white', font='none 12 bold').grid(row=0, column=0, sticky=W)
           Label(arpwindow, text="Source Hardware Address", bg='black', fg='white', font='none 12 bold').grid(row=1, column=0, sticky=W)
           sourceentry = Entry(arpwindow, width=20, bg='white')
           sourceentry.grid(row = 1, column = 1, sticky = W)
           Label(arpwindow, text="Destination IP", bg='black', fg='white', font='none 12 bold').grid(row=2, column=0, sticky=W)
           destinationentry = Entry(arpwindow, width=20, bg='white')
           destinationentry.grid(row = 2, column = 1, sticky = W)
           output = Listbox(arpwindow, width=60)
           output.grid(row=4, column = 0, sticky = W)
           def click():
               source = sourceentry.get()
               if not valid_hw(source):
                   tkMessageBox.showerror("Error","Enter valid Source MAC Address")
                   return
               destination = destinationentry.get()
               if not valid_ip(destination):
                   tkMessageBox.showerror("Error","Enter valid Destination IP")
                   return
               packet = ARPpacket(source, destination)
               output.insert(END, packet.summary()+'\n')
           Button(arpwindow, text="Submit", width=6, command=click).grid(row=3,column=1,sticky=W)

           def click_quit():
               arpwindow.destroy()
               tk.destroy()
               exit()
           Button(arpwindow, text="QUIT", width=6, command=click_quit).grid(row=10,column=5,sticky=W)
           arpwindow.mainloop()

	#READ PACKETS
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
