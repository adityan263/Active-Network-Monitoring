from tkinter import *

window = Tk()
window.title("PROJECT")
window.configure(background='black')


textentry = Entry(window, width=70, bg='white')
textentry.grid(row = 3, column = 0, sticky = W)

def click():
	entered_text=textentry.get()
	output.delete(0.0, END)
	output.insert(END, entered_text)


Button(window, text="submit", width=6, command=click).grid(row=4,column=0,sticky=W)

Label(window, text="OUTPUT", bg='black', fg='white', font='none 12 bold').grid(row = 5, column=0,sticky=W)

output = Text(window, width=75, height=6, wrap=WORD, background='white')
output.grid(row=6, column = 0, sticky = W)


Label(window, text="EXIT", bg='black', fg='white', font='none 12 bold').grid(row = 7, column=0,sticky=W)

def close_window():
	window.destroy()
	exit()

Button(window, text="QUIT", width=6, command=close_window).grid(row=8,column=0,sticky=W)


window.mainloop()
