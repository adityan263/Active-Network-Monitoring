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
import ipgetter

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
    first = time.time()
    while not finish.is_set():
        raw_data, addr = conn.recvfrom(65535)
        ethernet = Ethernet(raw_data)
        if ethernet.proto == 8:
            #IPV4
            ipv4 = IPv4(ethernet.data)
            if ipv4.proto == 1:
                #Icmp
                icmp = ICMP(ipv4.data)
            elif ipv4.proto == 6:
                #Tcp
                tcp = TCP(ipv4.data)
                if tcp.src_port == 80 or tcp.dest_port == 80:
                    http = HTTP(tcp.data)
            elif ipv4.proto == 17:
                #Udp
                udp = UDP(ipv4.data)
            elif ipv4.proto == 88:
                #Igmp
                igmp = IGMP(ipv4.data)
            thelist.append((i, time.time()-first, ipv4.src_ip_addr,
                ipv4.target_ip_addr,dictionary[ethernet.proto], raw_data))
        elif ethernet.proto == 1544:
	    #Arp
            arp = ARP(ethernet.data)
            thelist.append((i, time.time()-first, "-",
                "-",dictionary[ethernet.proto], raw_data))
        elif ethernet.proto == 13576:
            #Rarp
            rarp = RARP(ethernet.data)
            thelist.append((i, time.time()-first,"-",
                "-",dictionary[ethernet.proto], raw_data))
        elif ethernet.proto == 56710:
            #Ipv6
            ipv6 = IPv6(ethernet.data)
            thelist.append((i, time.time()-first,ipv6.src_ip_addr,
                ipv6.dest_ip_addr,dictionary[ethernet.proto], raw_data))
        if saving.is_set():
            pcap.write(raw_data)
        i += 1
    pcap.close()

def main():
    tk = Tk()
    tk.title("Active Network Monitoring")
    tk.protocol("WM_DELETE_WINDOW",lambda:finish.is_set())
    choice = IntVar()
    choice.set(10)
    while choice.get() >= 10:
        tk.geometry("200x220")
        options = Frame()
        options.pack(anchor=CENTER)
        Label(options, text="Choose Feature",font='none 12 bold').pack()
        button1 = Button(options,text="Send Packets", command=lambda: choice.set(1))
        button2 = Button(options,text="Read Packets", command=lambda: choice.set(2))
        button3 = Button(options,text="Get Public IP", command=lambda: choice.set(3))
        button4 = Button(options,text="Quit", fg="red",command=lambda: choice.set(0))
        button1.pack(fill=X, side=TOP)
        button2.pack(fill=X, side=TOP)
        button3.pack(fill=X, side=TOP)
        button4.pack(fill=X, side=TOP)
        
        button1.wait_variable(choice)
        if choice.get():
            options.destroy()

        #SEND PACKETS
        if(choice.get() == 1):
            choice.set(21)
            while choice.get() > 20:
                options = Frame()
                tk.geometry("1200x800")
                options.pack()
                Label(options, text="Choose Packet-Protocol Format",font='none 12 bold').pack()
                button1 = Button(options,text="TCP", width = 25, command=lambda: choice.set(1))
                button2 = Button(options,text="UDP", width = 25, command=lambda: choice.set(2))
                button3 = Button(options,text="ICMP",width = 25, command=lambda: choice.set(3))
                button4 = Button(options,text="ARP",width = 25, command=lambda: choice.set(4))
                button4.pack(fill=X, side=TOP)
                button3.pack(fill=X, side=TOP)
                button1.pack(fill=X, side=TOP)
                button2.pack(fill=X, side=TOP)

                Button(options, text="BACK", width=25, command=lambda: choice.set(10)).pack(fill=X, side=TOP)
                Button(options, text="QUIT", width=25, command=lambda: choice.set(0)).pack(fill=X, side=BOTTOM)
                button1.wait_variable(choice)
                options.destroy()

                #SENDING TCP PACKET
                if(choice.get() == 1):
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
                            tkinter.messagebox.showerror("Error","Enter valid Destination IP")
                            return
                        sp = sport.get()
                        if not valid_port(sp):
                            tkinter.messagebox.showerror("Error","Enter valid Source-Port Number")
                            return
                        dp = dport.get()
                        if not valid_port(dp):
                            tkinter.messagebox.showerror("Error","Enter valid Destination-Port Number")
                            return
                        packet = TCPpacket(d,int(sp),int(dp))
                        output.insert(END, packet.summary()+'\n')
                        choice.set(6)
                    buttons = Button(tcpwindow, text="Submit", width=6, command=click)
                    buttons.grid(row=4,column=1,sticky=W)

                    Button(tcpwindow, text="Back", width=6, command=lambda:
                            choice.set(30)).grid(row=10,column=5,sticky=W)
                    Button(tcpwindow, text="QUIT", width=6, command=lambda:
                            choice.set(0)).grid(row=13,column=5,sticky=W)
                    while choice.get() > 0 and choice.get() < 30:
                        buttons.wait_variable(choice)
                    tcpwindow.destroy()

                #SENDING UDP PACKET
                elif(choice.get() == 2):
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
                            tkinter.messagebox.showerror("Error","Enter valid Destination IP")
                            return
                        sp = sport.get()
                        if not valid_port(sp):
                            tkinter.messagebox.showerror("Error","Enter valid Source-Port Number")
                            return
                        dp = dport.get()
                        if not valid_port(dp):
                            tkinter.messagebox.showerror("Error","Enter valid Destination-Port Number")
                            return
                        packet = UDPpacket(d,int(sp),int(dp))
                        output.insert(END, packet.summary()+'\n')
                    buttons = Button(udpwindow, text="Submit", width=6, command=click)
                    buttons.grid(row=4,column=1,sticky=W)
                    
                    Button(udpwindow, text="Back", width=6, command=lambda:
                            choice.set(30)).grid(row=10,column=5,sticky=W)
                    Button(udpwindow, text="QUIT", width=6, command=lambda:
                            choice.set(0)).grid(row=13,column=5,sticky=W)
                    while choice.get() > 0 and choice.get() < 30:
                        buttons.wait_variable(choice)
                    udpwindow.destroy()

                #SENDING ICMP PACKETS
                elif(choice.get() == 3):
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
                            tkinter.messagebox.showerror("Error","Enter valid Destination IP")
                            return
                        destination = destinationentry.get()
                        if not valid_ip(destination):
                            tkinter.messagebox.showerror("Error","Enter valid Destination IP")
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
                    buttons = Button(icmpwindow, text="Submit", width=6, command=click)
                    buttons.grid(row=4,column=1,sticky=W)
                    
                    Button(icmpwindow, text="Back", width=6, command=lambda:
                            choice.set(30)).grid(row=10,column=5,sticky=W)
                    Button(icmpwindow, text="QUIT", width=6, command=lambda:
                            choice.set(0)).grid(row=13,column=5,sticky=W)
                    while choice.get() > 0 and choice.get() < 30:
                        buttons.wait_variable(choice)

                    icmpwindow.destroy()

                #SENDING ARP packets
                elif(choice.get() == 4):
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
                            tkinter.messagebox.showerror("Error","Enter valid Source MAC Address")
                            return
                        destination = destinationentry.get()
                        if not valid_ip(destination):
                            tkinter.messagebox.showerror("Error","Enter valid Destination IP")
                            return
                        packet = ARPpacket(source, destination)
                        output.insert(END, packet.summary()+'\n')
                    buttons = Button(arpwindow, text="Submit", width=6, command=click)
                    buttons.grid(row=4,column=1,sticky=W)
                    
                    Button(arpwindow, text="Back", width=6, command=lambda:
                            choice.set(30)).grid(row=10,column=5,sticky=W)
                    Button(arpwindow, text="QUIT", width=6, command=lambda:
                            choice.set(0)).grid(row=13,column=5,sticky=W)
                    while choice.get() > 0 and choice.get() < 30:
                        buttons.wait_variable(choice)

                    arpwindow.destroy()


        elif(choice.get() == 2):
            #READ PACKETS
            tk.geometry("650x650")
            bttns = Frame()
            bttns.pack()
            paused = IntVar()
            mlb = MultiListbox(tk, (('No.', 5),('Time', 20), ('Destination', 20), ('Source', 20),
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
            button5 = Button(bttns,text="Back", command=lambda: choice.set(10))
            button4 = Button(bttns,text="Quit", fg="red",command=lambda: finish.set())
            button5.pack(side=LEFT)
            button4.pack(side=LEFT)
            text_frame = Frame()
            text_frame.pack()
            tex = Text(text_frame,width=454, height=50)
            tex.pack(side=BOTTOM)
            tk.update()
            t1 = threading.Thread(target=fillin)
            t1.start()
            while (not finish.is_set()) and choice.get() < 10:
                try:
                    mlb.insert(END, (thelist[i][0], thelist[i][1],
                        thelist[i][2], thelist[i][3], thelist[i][4]))
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
                    tex.insert(INSERT, thelist[globalvars.sel_row][5])
                    text_frame.update()
            finish.set()
            abc = 0
            if choice.get() == 10:
                abc = 10
            t1.join()
            bttns.destroy()
            tk.destroy()
            tk = Tk()
            tk.title("Active Network Monitoring")
            tk.protocol("WM_DELETE_WINDOW",lambda:finish.is_set())
            choice = IntVar()
            if abc:
                choice.set(10)
        elif(choice.get() == 3):
            print(ipgetter.myip())
    tk.destroy()

if __name__ == '__main__':
    #cProfile.run('main()')
    main()
