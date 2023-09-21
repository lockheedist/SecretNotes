from tkinter import *
from PIL import ImageTk, Image
from cryptography.fernet import Fernet

wn = Tk()
wn.title("Secret Notes @lockheedist")
wn.minsize(400,600)
wn.config(bg="white",)
#Image label
img = ImageTk.PhotoImage(Image.open("secsec.png"))
imagelabel= Label(image=img)
imagelabel.pack()

#title label and entry
titlelabel= Label(text="Enter your title")
titlelabel.pack()
titleentry= Entry()
titleentry.pack()

#textbox label and textbox
textboxlabel= Label(text="Write your Note")
textboxlabel.pack()
textbox= Text(width=40)
textbox.pack()

#keyentry label and entry
keylabel= Label(text="Enter Master Key")
keylabel.pack()
keyentry= Entry()
keyentry.pack()


#Save&Encrypt Button
saveenrcypt= Button(text="Save&Encrypt")
saveenrcypt.pack()


#Decrypt button
decrypt= Button(text="Decryption")
decrypt.pack()

titlegetintro = titleentry.get()
textandtitlegetintro= str(textbox.get("1.0",'end-1c'))+" "+str(titleentry.get())
message = "hi"
def keysappend():
    with open("keys.txt","at") as keys:
        keys.write(f"\ntest")

def generatedecrypt():
    message=str(textbox.get("1.0",'end-1c'))+" "+str(titleentry.get())
    key = Fernet.generate_key()
    fernet = Fernet(key)
    encMessage = fernet.encrypt(message.encode())



wn.mainloop()