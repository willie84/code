

# CSC4026Z Assignment 2020
# University of Cape Town
# AUTHORS - CHTBLE001 | MCHWIL006 | MDZMAP001 | NGMGER002

**Files Structure**
The assignment is made of two independent parts that is ClientA(Client) and ClientB(server for starting communication).

The source code can be found in the ClientA/src folder and ClientB/src folder. The two folders have five common files:
 1. PGPEncryption.java : This file contains the PGP Encryption implementation. Found in both ClientA and ClientB src Folders.
 2. PGPDecryption.java : This file contains the PGP Decryption implementation. Found in both ClientA and ClientB src Folders.
 3. PGPKeys.java : This file contains the PGP keys management implementation. Found in both ClientA and ClientB src Folders.
 4. Settings.java : This file contains the IP Address and port number configuration of both client and server. Found in both ClientA and ClientB src Folders.
 5. ClientA.java/ClientB.java: ClientA.java contains graphical user interface implementation of the client and ClientB.java contains graphical user interface implementation of the server.

 ClientB has another file: "ServerThread.java" which contains code for connecting server to the client. The thread class is extend to allow execution of exchanging of certificates prompted before formal communication could start.

 **Building, running a sample, cleaning**
 To run the code ensure the following are done:
 The project was developed using Netbeans IDE but it can be tested and run using other ways described below.
1. Ensure that the jar files of the bouncy castle libraries are installed. The project folder has the jar files already included in the Lib folder.
2. If you using an IDE to run the project or test it; ensure you build the project before running it. We recommend using linux command line to
    run the makefile which is used to automate the building processes.  You can either way open it in an IDE and run it from the IDE such as Intellij, Eclipse or Netbeans.

**running the code**
1. Invoke the building by running "make" on the command line of linux. It is a must to have installed 'ant' so to invoke the building process.
   'ant' is a apache building command for java projects. If you don't have it installed, run **sudo apt-install ant** in your machine

**Testing procedure**
1. Open your command line/prompt into two windows.
2. One window of the command prompt Run the "make server" command to invoke the automation of the building process of the server part of the project.
3. Second window of the command prompt Run the "make client" command to invoke the automation of the building process of the client part of the project.
4. Click the "Connect to ClientA" button on the ClientB graphical user interface.
5. Click the "Connect to ClientB" button on the ClientA graphical user interface.
 **The exchange of X.509 certificates will start immediately and verification will be completed**
 **Do not interchange step 3 and 4 because the server need to start communication first before the client".**
6. Type a message on the 'Message textbox' on ClientA graphical user interface and click "send" button.
**You will immediately see a pgp encrypted message on the ClientB encrypted message text-box GUI"**
7. Click the "Decrypt" button on ClientB
8. Click okay on message box of  signature verified
9. Click okay on message box of  message integrity passed
 **immediately the message that was sent by ClientA will appear**
