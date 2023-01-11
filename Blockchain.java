/*--------------------------------------------------------

1. Name / Date:
Tavis Sotirin-Miller
3/04/2020

2. Java version used, if not the official version for the class:

openjdk version "1.8.0_222"
OpenJDK Runtime Environment (AdoptOpenJDK)(build 1.8.0_222-b10)

3. Precise command-line compilation examples / instructions:

> javac -cp "gson-2.8.2.jar" Blockchain.java

4. Precise examples / instructions to run this program:

In separate shell windows:

> java -cp ".;gson-2.8.2.jar" Blockchain X

Where X is the process number (0,1,2)

Tested using .bat master file provided and worked fine

All acceptable commands are displayed on the various consoles.
R XXXXX - Reads in data from a file at the root directory called XXXXX
C - Prints out the number of blocks each process has verified. If a process did not contribute to any verifications, it is not displayed
L - Prints out the entire blockchain line by line (Block num, time created, data)

Defaultly runs on localhost only, so processes must be on the same machine

5. List of files needed for running the program.

 a. Blockchain.java 
 b. BlockInput0.txt (Only one txt file is needed to run and test everything, but multiple can be used)
 c. BlockInput1.txt (Only one txt file is needed to run and test everything, but multiple can be used)
 d. BlockInput2.txt (Only one txt file is needed to run and test everything, but multiple can be used)
 e. checklist-block.html (not necessary for running the program, but included in the zip file)
 f. BlockchainLog.txt (not necessary for running the program, but included in the zip file)

5. Notes:

Using the master .bat file provided all servers will start up and connect to each other, then broadcast and display their keys. After this any command can be run on any of them.

I had some issues with how the text is displayed when you are still able to enter a command. I'm not really sure how to resolve it since we want things to print out to the screen and they happen when you still should have control.
As such, when blocks are being received text will interrupt typing of commands, but it shouldn't change being able to enter them.

I also do not display the public keys sent, but instead just mention the process that sent them, because I found the RSA Public Key's print outs were huge and made everything awkward to read.

----------------------------------------------------------*/

import java.util.*;
import java.io.*;
import java.net.*;
import java.time.Clock;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.ZoneId;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.PatternSyntaxException;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.PriorityBlockingQueue; 
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.UUID;
import java.security.*;
import javax.crypto.Cipher;

public class Blockchain {
	static int processID;
	static KeyPair keys;
	static final PriorityBlockingQueue<Block> unverifiedBlocks = new PriorityBlockingQueue<Block>();
	static final CopyOnWriteArrayList<Block> verifiedBlocks = new CopyOnWriteArrayList<Block>();
	static final CopyOnWriteArrayList<UUID> verifiedBlocksIDs = new CopyOnWriteArrayList<UUID>();
	static final int keyPort = 4710;
	static final int ubPort = 4820;
	static final int vbPort = 4930;
	private static boolean initialSetup = true;
	static final int seed = (int)(Math.random() * 1000);
	static final Hashtable<Integer,PublicKey> publicKeyList = new Hashtable<Integer,PublicKey>();
	
	public static void main(String argv[]) {
		int q_len = 6;
		int listenPort[] = {0,0,0};
		
		// Set port numbers for listening for public keys, unverified blocks, and updated chains (array index 0,1,2, respectively)
		if (argv.length > 0) {
			processID = Integer.parseInt(argv[0]);
			if (processID == 0 || processID == 1 || processID == 2) {
				listenPort[0] = 4710 + processID;
				listenPort[1] = 4820 + processID;
				listenPort[2] = 4930 + processID;
			}
			else
				return;
		}
		else {
			System.out.println("Please provide at least one argument when launching this program");
			return;
		}
		
		ServerSocket sock = null;
		
		// Start up listener threads
		try {
			for (int port : listenPort)
				new ServerListener(new ServerSocket(port, q_len)).start();
		} catch (IOException x) {System.out.println("Error spawning server threads. Program shutting down"); return;}
		
		System.out.println("Multicast servers starting up. This is process " + processID);
		
		// Generate public/private key pair
		try {
			// Create key generator based on RSA algorithm
			KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
			// Create a java secure random number generator and set the seed to a random value the process picked when starting up. Real world we would want to avoid Math.Random as used above for safety
			SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
			rng.setSeed(seed);
			// Setup keygen with our random seeded object
			keyGenerator.initialize(1024, rng);
			// Generate the key pair for this process
			keys = keyGenerator.generateKeyPair();
		
			//cast public keys after launch
			mcast(Integer.toString(seed) + Integer.toString(processID), keyPort);
			initialSetup = false;
		} catch (Exception x) {System.out.println("Failed to initilize public/private key pair");}
		
		// Start thread to sit at priority queue and pull unverfied blocks as they fill up
		new BlockWorker().start();
		
		// Wait for client input
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		String input;
		String inArg = "";
		String inCom = "";
		boolean cont = true;

		// Basic user input switch to run different commands. Run this loop permanently for the rest of main's runtime
		do {
			System.out.println("Available commands: 'c' (List of processes with number of verified blocks), 'r XXXX' (Read in new data from file XXXX), 'l' (Print blockchain)");
			System.out.print("Enter console command with any needed arguments seperated by a single space: ");
			try {
				input = in.readLine().trim();
				
				try {
					inCom = input.split("\\s+",2)[0].trim().toLowerCase();
					inArg = input.split("\\s+",2)[1].trim();
				} catch (IndexOutOfBoundsException | PatternSyntaxException x) {inCom = input.toLowerCase();}
				
				switch (inCom) {
					case "c": 
						verifyCredit();
						break;
					// Read given input file to create a new block based on the data in that file. Expecting data to appear line by line, with each line represented as a unique unverified block
					case "r": 
						int count = createBlock(inArg);
						System.out.println(count + ((count == 1) ? " record was " : " records were ") + "added to unverified block list.\n");
						break;
					case "l": 
						printBlockchain();
						break;
					default:
						System.out.println("Invalid entry");
				}
				
				inArg = "";
				inCom = "";
			} catch (IOException x) {System.out.println("Error reading input from client. Try again.");}
		} while (cont);
	}
	
	// https://www.geeksforgeeks.org/sha-256-hash-in-java/
	// Code pulled from website above as it made more since to me than what was provided. The logic is very similiar though.
	// Produce a 256 hash of any string given
	public static String produceHash(String data) throws NoSuchAlgorithmException {
		byte[] hash = null;
		
		// Set up message digest used to create a hash based on a provided algorithm, in this case SHA256
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		
		// Store the returned bytes as a BigInteger (just an int that can be larger than the primitives max size)
		BigInteger hashedNum = new BigInteger(1, digest.digest(data.getBytes(StandardCharsets.UTF_8)));  
  
        // Interpret the integer above as hexadecimal  
        StringBuilder hexString = new StringBuilder(hashedNum.toString(16));
  
        // To ensure hash is 256 bits, pad the beginning of our hex string with 0's if we are under 32 bytes
        while (hexString.length() < 32)
			hexString.insert(0, '0');  
  
        return hexString.toString();
	}
	
	// Create new unverified blocks based on data from a given input file
	public static int createBlock(String filename) {
		int count = 0;
		// Open/create a file at our root
		String path = System.getProperty("user.dir") + "\\" + filename;
		
		// Add .txt if it wasn't typed in. If file path is invalid an error will report to user, if not the data will be read line by line and then multicast out to all processes as new blocks
		try {
			if (filename.indexOf(".txt") <= 0)
				path += ".txt";
			
			File openFile = new File(path);
			
			// Read each line of the opened file and mcast a new block based on that data out
			for (String s : Files.readAllLines(Paths.get(openFile.getPath().trim()), StandardCharsets.UTF_8)) {
				mcast(new Block(s), ubPort);
				count++;
			}
			
		} catch (IOException x) {System.out.println("Error reading file at:\n" + path + "\nPlease make sure file exists, is of type '.txt', name was entered correctly, and file exists in this programs' root directory.");}
		
		// Used to tell how many new blocks were made
		return count;
	}
	
	// Write entire blockchain to .json file
	public static void blockchainToFile() {
		try {
			// Create new gson object using pretty printing since it will be read
			Gson gson = new GsonBuilder().setPrettyPrinting().create();
			
			Path path = Paths.get(System.getProperty("user.dir") + "\\" + "BlockchainLedger.json");
			
			// Get byte array of converted blockchain object and save to our path above
			byte[] strToBytes = gson.toJson(verifiedBlocks).getBytes();
			Files.write(path, strToBytes);
			
		} catch (IOException x) {System.out.println("Error writing blockchain to file");}
	}

	// Use block class toString method to print each block in the chain to the console
	public static void printBlockchain() {
		for (Block b : verifiedBlocks)
			System.out.println(b.toString());
	}
	
	// Used to keep code a little cleaner. Create a new McastSender object which will broadcast the object given at the specified port
	public static void mcast(Object obj, int port) {
		McastSender sender = new McastSender(obj,port);
		sender.start();
		
		// During initial launch (only done once), join and sleep will prevent text from overlapping with key prints to console
		if (initialSetup) {
			try { 
				sender.join();
				Thread.sleep(100);
			} catch (Exception e) {};
		}
	}
	
	// Print verified block counts per process to screen. If a process hasn't verified anything its ID won't be displayed
	public static void verifyCredit() {
		Hashtable<String,Integer> processCredit = new Hashtable<String,Integer>();
		
		// Running through chain, add the verifying process and increment its counter (unless the process has not been added before, in which case set counter to 1)
		for (Block b : verifiedBlocks)
			processCredit.compute(b.getVerifyingProcessID(), (key, val) -> ((val == null) ? 1 : (val + 1)));
		
		// Everything below is just formatting the output by iterating through the hashtable we used to store the counts
		String output = "Verification credit: ";

		for (String p : processCredit.keySet())
			output += "P" + p + " = " + processCredit.get(p) + "; ";
		
		try {
			output = output.substring(0,output.length()-2);
		} catch (Exception x) {output = "";}
		
		// Final tally print
		System.out.println(output);
	}

	// Decrypt method using publickey - not implemented for this assignment but was used for testing and curiousity
	// NOTE TO SELF: ONLY VALID FOR 128 BYTES
	public static String decrypt(byte[] text, PublicKey key) {
		byte[] decryptedText = null;
		try {
			// Using the RSA algorithm...
			final Cipher cipher = Cipher.getInstance("RSA");
			// ...inialize a cipher object using our public key...
			cipher.init(Cipher.DECRYPT_MODE, key);
			// ...and decrpyt the provided bytes
			decryptedText = cipher.doFinal(text);
		} catch (Exception e) {e.printStackTrace(); System.out.println("Error decrypting data");}
		
		return new String(decryptedText);
	}
	
	// Encrypt method using privatekey (signing) - not implemented for this assignment but was used for testing and curiousity
	// NOTE TO SELF: ONLY VALID FOR 128 BYTES
	public static byte[] encrypt(String text) {
		PrivateKey key = keys.getPrivate();
		byte[] cipherText = null;
		try {
			// Using the RSA algorithm...
			final Cipher cipher = Cipher.getInstance("RSA");
			// ...inialize a cipher object using our private key...
			cipher.init(Cipher.ENCRYPT_MODE, key);
			// ...and encrypt the provided string converted into bytes
			cipherText = cipher.doFinal(text.getBytes());
		} catch (Exception e) {System.out.println("Error encrypting data");}
		return cipherText;
	}
}

// BlockWorker continually sits at the blocking method 'take' from the priority queue waiting for new unverifed blocks to placed. Once it pulls one it runs the verify method built into the block class
class BlockWorker extends Thread {
	public boolean check = true;
	
	public void run() {
		// For this assignment never stop loop
		do {
			try {
				// Pull blocks out of queue - blocking
				Block curBlock = Blockchain.unverifiedBlocks.take();
				
				// Check to make sure the block we just pulled wasn't verified already - verifiedBlockID is just a list of the UUID's sitting in the chain, used to make this lookup a little quicker
				if (!Blockchain.verifiedBlocksIDs.contains(curBlock.getUUID())) {
					// Run verify on the block - blocking until complete
					curBlock.verifyBlock();
					// Check to make sure the block we just verified wasn't verified while we worked on it
					if (!Blockchain.verifiedBlocksIDs.contains(curBlock.getUUID())) {
						// If the block isn't in the chain, make sure we finished the verification
						if (curBlock.getVerfied())
							// Then cast it out to the other process as a valid block
							Blockchain.mcast(curBlock,Blockchain.vbPort);
						else
							// Otherwise put it back in the queue
							Blockchain.unverifiedBlocks.add(curBlock);
					}
				}
			} catch (InterruptedException x) {};
		} while (check);
	}
}


// Listens for any type of casts from other processes (including self)
// The logic for what got sent will be dealt with in the acceptor class, so all listeners are the same save for port number
class ServerListener extends Thread {
	ServerSocket serverSock;
	Socket clientSock;
	
	ServerListener(ServerSocket sock) {serverSock = sock;}
	
	public void run() {
		while (true) {
			try {
				// After receiving a cast spin up an Acceptor to handle it and go back to listening
				clientSock = serverSock.accept();
				new McastAcceptor(clientSock).start();
			} catch (IOException x) {continue;};
		}
	}
}

// After a cast is received, perform different logic based on what was sent (using port number)
class McastAcceptor extends Thread {
	private int port;
	private int id;
	private Socket clientSock;
	
	// listenPort ignores last digit (process number) to ease logic switching
	McastAcceptor(Socket sock) {clientSock = sock; port = sock.getLocalPort() / 10; id = sock.getLocalPort() % 10;}
	
	public void run() {
		// Create gson object and streams
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		ObjectOutputStream outObj = null;
		ObjectInputStream inObj = null;
		String sentObject = "";
		
		try {
			outObj = new ObjectOutputStream(clientSock.getOutputStream());
			inObj = new ObjectInputStream(clientSock.getInputStream());
			
			// Read JSON string in
			sentObject = (String) inObj.readObject();
		} catch (ClassNotFoundException | IOException x) {System.out.println("Error occured while recieving data over network"); return;}
		
		// At this point we branch based on the port of the connecting client, indicating what type of object was sent and how we will deal with it
		switch(port) {
			// Public keys
			// I was having issues unmarshalling the public key objects, so as a workaround I send the random seed used to create the key from the other process, then recreate it here. Since it's seeded, as long as it's set up the same and given the same seed, it will always produce the same key
			// Obviously this is a terrible way to send these keys as I am also technically sending the private key over the network as well, but for this assignment I think it should be ok
			case 471:
				try {
					// Pull seed from network and cast as int
					String temp = gson.fromJson(sentObject,String.class);
					Integer id = Integer.parseInt(temp.substring(temp.length()-1));
					Integer publicSeed = Integer.parseInt(temp.substring(0,temp.length()-1));
					
					// Construct key gen and keys based on seed - same as in main
					KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
					SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
					rng.setSeed(publicSeed);
					keyGenerator.initialize(1024, rng);
					
					PublicKey key = keyGenerator.generateKeyPair().getPublic();
					
					// Add this publickey to our list using the processID as the hash key
					Blockchain.publicKeyList.compute(id, (k, v) -> ((v == null) ? key : v));
					// Inform user a key was received
					System.out.println("Received public key from process " + id);
				} catch (Exception x) {};
				break;
			// Unverified blocks
			case 482:
				// Unmarshal the block as a Block object and add it to our queue
				Blockchain.unverifiedBlocks.add(gson.fromJson(sentObject,Block.class));
				break;
			// Updated blockchain
			// Sending only a single updated block instead of the whole chain
			case 493:
				System.out.println("Verified blockchain has been updated through reciept of a new block");
				
				// Unmarshal block from JSON and add to our verified blockchain, as well its UUID to our UUID list
				Block temp = gson.fromJson(sentObject,Block.class);
				Blockchain.verifiedBlocks.add(temp);
				Blockchain.verifiedBlocksIDs.add(temp.getUUID());
				
				// If we are process 0, write entire blockchain to disk in JSON format
				if (Blockchain.processID == 0)
					Blockchain.blockchainToFile();
				
				break;
			default:
				break;
		}
	}
}

// Cast out data to other processes (including self)
// Since sending a JSON string over the network is the same regardless of the object we are sending, this class is non-unique per cast type
class McastSender extends Thread {
	Object toSend = null;
	int ports[] = {0,0,0};
	
	// Set ports using provided base (4710,4820,4930)
	// Since we want to send to everyone we are just adding 0,1,2 to those numbers for our port list, but to expand we would just store the port of any known client and use that list instead
	McastSender(Object o, int p) {
		toSend = o;
		ports[0] = p + 0;
		ports[1] = p + 1;
		ports[2] = p + 2;
	}
	
	public void run() {
		// Create gson object to marshal
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		// Create JSON string for the object given to us
		String toSendStr = gson.toJson(toSend);
		
		// Start connection(s)
		for (int p : ports) {
			// Start in/out stream
			Socket sock = null;
			ObjectOutputStream servOut = null;
			ObjectInputStream servIn = null;
			boolean connected = false;
			int count = 0;
			
			// Connect to the various ports (one at a time). Continue to try for a set amount of tries before assuming the corresponding server is offline
			do {
				try {
					connected = true;
					sock = new Socket("localhost", p);
				} catch (Exception x) {connected = false; count++;}
			} while (!connected && count < 10);
			
			// Write our JSON string to the server
			try {
				servOut = new ObjectOutputStream(sock.getOutputStream());
				servIn = new ObjectInputStream(sock.getInputStream());
				
				servOut.writeObject(toSendStr);
				servOut.flush();
			} catch (Exception x) {System.out.println("Could not connect at port " + p + " to send object"); continue;}
		}
	}
}

// Main block class - comparable interface used for sorting in priority queue - see compareTo method
class Block implements Comparable<Block> {
	private final UUID blockID = UUID.randomUUID();
	// Have we been verified?
	private boolean verified = false;
	private String data;
	private String lastHash = "0000000000000000000000000000000000000000000000000000000000000000";
	private String hash;
	// Working guess
	private int seed;
	// Time block was created using system clocks most accurate measurement. This is timezone independant, so it shouldn't matter where the creating process exists, these will all correspond to each other correctly
	private final Instant timeCreated = Clock.systemUTC().instant();
	// How difficult we want our puzzle
	private static final int workVal = 100;
	private final String creatingProcessID = Integer. toString(Blockchain.processID);
	private String verifyingProcessID;
	private int blockNumber;

	Block(String s) {
		this.data = s;
	}
	
	// Public getter methods
	public UUID getUUID() {
		return blockID;
	}
	public String getData() {
		return data;
	}
	public String getHash() {
		return hash;
	}
	public String getLastHash() {
		return lastHash;
	}
	public String getProcessID() {
		return creatingProcessID;
	}
	public String getVerifyingProcessID() {
		return verifyingProcessID;
	}
	public boolean getVerfied() {
		return verified;
	}
	
	// Used while verifying - updates lashHash based on most recent block in blockchain. If there are none, leaves lastHash as 0's
	private String updatePrevious() {
		Block prevBlock = null;
		
		try {
			prevBlock = Blockchain.verifiedBlocks.get(Blockchain.verifiedBlocks.size()-1);
		} catch (ArrayIndexOutOfBoundsException x) {prevBlock = null;}
		
		lastHash = (prevBlock == null) ? lastHash : prevBlock.getHash();
		
		return lastHash;
	}
	
	// Get latest blockchain block's block number for verification. If the verified block list is empty, latest block number is 0, otherwise, our number should be the old number + 1
	protected int getBlocknumber() {
		try {
			blockNumber = Blockchain.verifiedBlocks.get(Blockchain.verifiedBlocks.size()-1).blockNumber + 1;
		} catch (Exception x) {blockNumber = 0;}
		
		return blockNumber;
	}

	// After we have succesfully verified ourselves update our final hash, verified, and verifying process ID values
	protected void setVerified() {
		try {
			hash = Blockchain.produceHash(blockNumber + data + lastHash + Integer.toHexString(seed));
			verified = true;
			verifyingProcessID = Integer.toString(Blockchain.processID);
		} catch (NoSuchAlgorithmException x) {System.out.println("Error verifying block");}
	}
	
	// Override default toString method for nicer printing. DateTimeFormatter used to convert our instant time created field. Sets time to system clocks timezone
	@Override
    public String toString() {
        return (blockNumber + ". " + DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS").withZone(ZoneId.systemDefault()).format(timeCreated) + " " + data);
    } 
	
	// Implement Comparable interface compareTo function to create a natural ordering for the priority queue sorting of unverified blocks.
	// Order is based on time the block was created using the system clocks most accurate time value available, ignoring timezones
	// If the time created was identical between the 2 blocks, compare the process ID's that created the blocks and choosing the lower one 
	// (Since a process can't have created 2 blocks at the exact same time, this will ensure a consistent sorting for the unverified blocks)
	public int compareTo(Block b) {
        return (timeCreated.compareTo(b.timeCreated) == 0) ? creatingProcessID.compareTo(b.creatingProcessID) : timeCreated.compareTo(b.timeCreated);
    }
	
	// Verify block - i.e. do work to solve a hash puzzle. Based on our block number, our data, the last block hash, and some seed
	public void verifyBlock() {
		// Set hashable data
		String blockData = getBlocknumber() + data + updatePrevious();
		// Set above the value we are checking against to start
		int verifyVal = workVal + 1;
		
		do {
			// Random seed for our working guess
			seed = (int)(Math.random() * 10000);
			try {
				// Hash our data and our seed and interept them as a hex value
				BigInteger hashVal = new BigInteger(Blockchain.produceHash(blockData + seed), 16);
				String hashValStr = hashVal.toString();
				// Pull the last 5 digits of our hex value interepted as an integer
				verifyVal = Integer.parseInt(hashValStr.substring(hashValStr.length()-5));
				
				// Micro sleep to slow the work down artificially - work can be made harder and  this can be removed, but I found 1ms to be a good balance of time to solve
				try {
					Thread.sleep(1);
				} catch (InterruptedException x) {};
				
			} catch (NoSuchAlgorithmException x) {System.out.print("Error occured while verifying block.");}
		// Continue with a new guess if the last 5 digits interpreted as an integer are not greater than our predefined difficulty above
		} while (verifyVal > workVal);
		
		try {
			Thread.sleep(1000);
		} catch (InterruptedException x) {};
		
		int blockCheck = -1;
		// Check to make sure a block didn't get added to the chain while we were working
		try {
			blockCheck = Blockchain.verifiedBlocks.get(Blockchain.verifiedBlocks.size()-1).blockNumber + 1;
		} catch(Exception x) {blockCheck = 0;}
		// If one didn't get added, set our verified status and return
		if (blockNumber == blockCheck) {
			setVerified();
		}
	}
}