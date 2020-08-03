/*
 * THE TFTP PROTOCOL (Client side).
 *
 * Based on RFC 1350 at https://www.ietf.org/rfc/rfc1350.txt with some
 * simplifications. A simple file transfer protocol that reads or writes
 * files to another server working solely under octet mode, passing raw 8 bit
 * bytes of data, and implemented on top of the Internet User Datagram Protocol
 * (UDP / Datagram). Works in parallel with exactly one remote server at a time.
 *
 * Assignment 2: Implementation of the Trivial File Transfer Protocol
 * (TFTP) of G5115 Computer Networks, University of Sussex, Spring 2020.
 * Deadline: May 08, 2020.
 *
 * @author 223459 afd22@sussex.ac.uk
 * @version 1.0 %G%, %U%.
 * */
package transport;

import java.io.*;
import java.net.*;
import java.util.Scanner;

/**
 * This class acts as the main body of the Client side of this TFTP protocol.
 *
 * @author 223459 afd22@sussex.ac.uk
 * @version 1.0 %G%, %U%.
 * */
public class TFTPClient {
    /** Main socket of this client for this TFTP session. */
    private static DatagramSocket socket;
    /** Default byte-size of a DATA block packet, by RFC 1350. */
    private static final int DEFAULT_DATA_SIZE = 512;
    /** Default server master port for initializing any TFTP sessions based
     * on RFC 1350. */
    private static final int DEFAULT_SERVER_PORT = 69;

    /** Internet address of target remote server. */
    private static InetAddress serverAddr;
    /** Scanner to scan for user input. */
    private static final Scanner SCAN = new Scanner(System.in);
    /** The hard limit placed the number of attempts to send the final DATA
     * block. It is presumed after this limit, the server has received all
     * needed data and been repeatedly attempting to send the final ACK. */
    private static final int FINAL_LOOP_LIMIT = 20;
    /** Hostile feature. Sets the probability a packet will not be sent to
     * determine the robustness of this protocol. 0.0 means no packet is
     * stopped and 1.0 means all packets will not be sent. */
    private static final double LOST_PROBABILITY = 0.0;

    /** The time value in milliseconds to raise the SocketTimeout exception. */
    private static final int TIMEOUT = 100;
    /** The hard limit placed on the amount of times this client will attempt
     * to send a read or write request to the server before presuming the
     * server is offline and terminating. */
    private static final int CLIENT_BRAKE = 100;
    /** Ports 1024 - 49151 are the User Ports and are the ones to use for the
     * protocols. Ports below 1024 are the Well Known Ports and above 49151
     * are the Dynamic ports. */
    private static final int MIN_PORT = 1024;
    /** Ports 1024 - 49151 are the User Ports and are the ones to use for the
     * protocols. Ports below 1024 are the Well Known Ports and above 49151
     * are the Dynamic ports. */
    private static final int MAX_PORT = 49151;

    /**
     * Main method.
     * @param args arguments input in terminal. No arguments expected.
     * @throws IOException if an I/O error occurs.
     * */
    public static void main(String[] args) throws IOException {
        System.out.println("\nClient started...");
        run();
        System.out.println("Client terminated.");
    }

    /**
     * Runs the main process.
     * @throws IOException if an I/O error occurs.
     * */
    private static void run() throws IOException {
        System.out.println();
        System.out.print("Please enter \"WRQ\" (without "
                + "quotes) for writing files to the server, or \"RRQ\" "
                + "(without quotes) for requesting files from the server: ");
        String response = SCAN.nextLine();
        System.out.println();

        if (response.equals("WRQ")) {
            init();
            writeRequest();
        } else if (response.equals("RRQ")) {
            init();
            readRequest();
        } else {
            System.err.println("Enter \"WRQ\" (without quotes) or \"RRQ\" "
                    + "(without quotes) only.");
            socket.close();
            System.exit(-1);
        }
        socket.close();
    }

    /**
     * Sets the remote server's internet address from the user's input. Allows
     * for the user to choose the DEFAULT value of the loopback address
     * 127.0.0.1 or to enter their preferred addresses.
     *
     * @throws IOException if an I/O error occurs.
     * */
    private static void init() throws IOException {
        System.out.print("Please input target server's IP Address or type "
                + "\"DEFAULT\" (without quotes) to use the loopback address "
                + "127.0.0.1: ");
        String responseInit = SCAN.nextLine();
        System.out.println();

        if (responseInit.equals("DEFAULT")) {
            serverAddr = InetAddress.getByName("127.0.0.1");
        } else {
            serverAddr = InetAddress.getByName(responseInit);
        }

        System.out.print("Please input this client's port number between "
                + "1024 and 49151 inclusive: ");
        int thisPort = Integer.parseInt(SCAN.nextLine());
        if (thisPort < MIN_PORT || thisPort > MAX_PORT) {
            System.out.println("Pick only between 1024 and 49151 inclusive.\n");
            System.out.println("Terminating client...\n\nClient Terminated.");
            System.exit(-1);
        } else {
            socket = new DatagramSocket(thisPort);
        }
    }

    /**
     * The main write method on the Client side. Processes a single request
     * to write a file in the server. After receiving initial acknowledgement
     * to write (ACK 0), DATA packets in octet mode are sent one at a time,
     * waiting for respective acknowledgements before another is sent.
     *
     * This process terminates once the final acknowledgement is received, or if
     * the final DATA packet has been sent above FINAL_LOOP_COUNT times, when
     * the server is presumed to have received the packet and kept failing to
     * send the final acknowledgement.
     *
     * Socket timeouts are initialized and handled here.
     *
     * @throws IOException if an I/O error occurs.
     * */
    private static void writeRequest() throws IOException {
        System.out.println("Write request initiated...");
        System.out.println();
        int blockNumber = 0;
        int expectedAck = blockNumber;
        int serverPort;
        DatagramPacket packetInLine;
        FileReader file;

        // user enters filename to write to server
        System.out.print("Enter filename to write to the server: ");
        String filename = SCAN.nextLine();
        System.out.println("Filename to write: " + filename + ".\n");

        // verify file exists; if not, a single ERROR packet is sent as courtesy
        try {
            file = new FileReader(filename);
        } catch (FileNotFoundException foe) {
            System.out.println("ERROR 071: File " + filename + " not found. "
                    + "Terminating client...\n");
            return;
        }

        // sends the WRQ to the server until an ACK 0 is received
        serverPort = sendWRQ(filename);
        expectedAck++;
        blockNumber++;

        //--------------------------write files---------------------------------

        // makes a BufferedReader to read content of file
        BufferedReader rdr = new BufferedReader(file);

        // reading file in 512 bytes
        char[] readBuf = new char[DEFAULT_DATA_SIZE]; // = 512
        int readCount;

        // how many times server sent final data packet
        int loopCount;

        // while not end of file, read in 512-byte blocks
        while ((readCount = rdr.read(readBuf, 0, readBuf.length)) != -1) {
            if (blockNumber != expectedAck) {
                System.out.println("ERROR 567: blockNumber " + blockNumber
                        + " != expectedAck " + expectedAck + ".");
                rdr.close();
                file.close();
                socket.close();
                System.exit(-1);
            }
            loopCount = 0;

            // keep sending the data packet until an ACK is received
            while (true) {
                try {
                    // sends a packet filled with 516-byte-or-less file data
                    packetInLine = produceDataPacket(readBuf, readCount,
                            blockNumber);
                    udtSend(packetInLine, serverPort, serverAddr);

                    if (readCount < DEFAULT_DATA_SIZE) {
                        System.out.println("Last data packet "
                                + blockNumber + " sent ["
                                + socket.getLocalPort() + ", " + serverPort
                                + "].\n");
                    } else {
                        System.out.println("Data packet "
                                + blockNumber + " sent ["
                                + socket.getLocalPort() + ", " + serverPort
                                + "].\n");
                    }

                    // receive ACK for sent data
                    byte[] bufAck = (receiveAck(expectedAck, packetInLine))
                            .getData();

                    // move on to next data block if expected ACK received
                    // else, resend the packet in line
                    int blockReceived = fromByteToInt(new byte[]{bufAck[2],
                            bufAck[3]});
                    if (blockReceived == expectedAck) {
                        blockNumber++;
                        expectedAck++;
                        break;
                    }
                } catch (SocketTimeoutException soe) {
                    // repeat cycle until receive ACK
                    System.out.println("NOTE 891: Timeout. Resending packet "
                            + blockNumber + ".");
                    // if final data block is consistently not acknowledged,
                    // presumed Server is terminated & all data received
                    if (loopCount > FINAL_LOOP_LIMIT
                            && readCount < DEFAULT_DATA_SIZE) {
                        System.out.println("\nloopCount = " + loopCount);
                        System.out.println("\nLast block sent too frequently."
                                + " Server presumed terminated.\n");
                        break;
                    }
                }
                loopCount++;
            }
        }
        rdr.close();
        file.close();

        // if file size multiple of 512 bytes, a last data packet of 0-byte
        // size will be sent
        boolean fileMultipleOfBlockSize =
                (new File(filename)).length() % DEFAULT_DATA_SIZE == 0;
        if (fileMultipleOfBlockSize) {
            System.out.println("NOTE 907: File size multiple of "
                    + DEFAULT_DATA_SIZE + " bytes.");
            readBuf = new char[0];
            packetInLine = produceDataPacket(readBuf, 0, blockNumber);

            // how many times server sent final data packet
            loopCount = 0;

            // resend until ACK received
            while (true) {
                try {
                    udtSend(packetInLine, serverPort, serverAddr);
                    System.out.println("Last data packet "
                            + blockNumber + " sent [" + socket.getLocalPort()
                            + ", " + serverPort + "].\n");
                    // receive ACK for sent data
                    receiveAck(expectedAck, packetInLine);
                    break;
                } catch (SocketTimeoutException soe) {
                    System.out.println("NOTE 304: Timeout. Resending block "
                            + blockNumber + ".");
                    // if final data block is consistently not acknowledged,
                    // presumed Server is terminated & all data received
                    System.out.println("\nloopCount = " + loopCount);
                    if (loopCount > FINAL_LOOP_LIMIT) {
                        System.out.println("\nLast block sent too frequently."
                                + " Server presumed terminated.\n");
                        break;
                    }
                }
                loopCount++;
            }
        }
    }

    /**
     * The main read method on the Client side. Processes a single request
     * to read a file from the server. DATA packets in octet mode are
     * received and separate acknowledgements are received for each before
     * another DATA packet can be received. After the final DATA packet (size
     * less than DEFAULT_DATA_SIZE) is received, the file is built and
     * completed. Dallying is used to leave the socket open for 10 * TIMEOUT if
     * the Server has yet to receive the last ACK.
     *
     * Socket timeouts are initialized and handled here.
     *
     * @throws IOException if an I/O error occurs.
     * */
    private static void readRequest() throws IOException {
        System.out.println("Read request initiated...");
        int blockExpected = 1;
        int blockReceived;
        int accessServerCount = 0;
        String filename;
        StringBuilder fileContent = new StringBuilder(DEFAULT_DATA_SIZE);
        byte[] totalBuf = new byte[DEFAULT_DATA_SIZE + 4];


        // getting filename
        System.out.print("Enter filename to read e.g. bob.txt: ");
        filename = SCAN.nextLine();
        System.out.println();

        // generate RRQ Packet
        DatagramPacket rrqPacket = generateRequestPacket(Opcode.RRQ,
                filename);

        // 'received' is the 1st data
        DatagramPacket received = new DatagramPacket(totalBuf,
                totalBuf.length);

        socket.setSoTimeout(TIMEOUT);
        while (true) {
            try {
                // sends the RRQ to the server
                udtSend(rrqPacket, DEFAULT_SERVER_PORT, serverAddr);
                socket.receive(received);
                break;
            } catch (SocketTimeoutException soe) {
                if (accessServerCount > CLIENT_BRAKE) {
                    System.out.println("\nServer not responding. Terminating "
                            + "client...\n");
                    return;
                }
                System.out.println("NOTE 891: Timeout. Resending RRQ take "
                        + accessServerCount + ".");
            }
            accessServerCount++;
        }
        socket.setSoTimeout(0); // no timeout after RRQ acknowledged

        // fix server slave port number
        int serverPort = received.getPort();
        socket.connect(received.getAddress(), serverPort);

        //---------------------------receive--------------------------------

        while (true) {
            // if opcode is not DATA, terminate Client
            if (!verifyPacketOpcode(received, Opcode.DATA)) {
                return;
            }

            // send ACK after verifying block number; if less than
            // expected, resend  ACK; if more than expected, declare
            // missing block and exit
            byte[] blockEncoded = {totalBuf[2], totalBuf[3]};
            blockReceived = fromByteToInt(blockEncoded);
            //System.out.println("blockReceived = " + blockReceived + "\n");

            if (blockReceived == blockExpected) {
                sendACK(blockReceived, serverPort);

                // building file content
                String dataReceived = new String(received.getData(), 0,
                        received.getLength());
                fileContent.append(dataReceived.substring(4));
                blockExpected++;
            } else if (blockReceived < blockExpected) {
                System.out.println("NOTE 208: Duplicate. Packet's block "
                        + "received " + blockReceived + " < block "
                        + "expected " + blockExpected + ".");
                sendACK(blockReceived, serverPort);
            } else { // blockReceived > blockExpected
                System.err.println("ERROR 301: A previous block of "
                        + "data is missing.");
                socket.close();
                System.exit(-1);
            }

            // if last block, break
            if (received.getLength() < DEFAULT_DATA_SIZE + 4) {
                System.out.println("Block " + blockReceived + " received"
                        + " from TID/port " + received.getPort() + ". "
                        + "Final ACK " + blockReceived + " sent ["
                        + socket.getLocalPort() + ", " + serverPort + "].\n");
                break;
            } else {
                System.out.println("Block " + blockReceived + " received"
                        + " from TID/port " + received.getPort() + ". ACK "
                        + blockReceived + " sent [" + socket.getLocalPort()
                        + ", " + serverPort + "].\n");
            }

            // receives next file from server, assuming no corruption and
            // possible loss
            received = new DatagramPacket(totalBuf, totalBuf.length);
            do {
                socket.receive(received);
            } while (!verifySocAddr(received, serverPort, serverAddr));
        }

        // write file that was read
        FileWriter myWriter = new FileWriter(filename);
        myWriter.write(String.valueOf(fileContent));
        myWriter.close();
        System.out.println("File " + filename + " successfully received "
                + "and read (copied). Terminating client.");
        System.out.println();

        // if the last ACK wasn't successfully transmitted, the socket will keep
        // open until the sender stops sending DATAs for sender's 10 * TIMEOUT
        socket.setSoTimeout(10 * TIMEOUT);
        while (true) {
            try {
                DatagramPacket finalDuplicate = new DatagramPacket(totalBuf,
                        totalBuf.length);
                socket.receive(finalDuplicate);
                if (verifySocAddr(finalDuplicate, serverPort, serverAddr)) {
                    byte[] blockEncoded = {totalBuf[2], totalBuf[3]};
                    blockReceived = fromByteToInt(blockEncoded);
                    System.out.println("NOTE 110: Received duplicate of final"
                            + " DATA block " + blockReceived + ".\n");
                    sendACK(blockReceived, serverPort);
                }
            } catch (SocketTimeoutException soe) {
                break;
            }
        }
    }

    // ==========================helper methods=================================

    /**
     * Returns the opcode of a TFTP operation in byte[] form, based on RFC 1350.
     *
     * @param opcode the operation in request.
     * @return opcode of operation.
     * @see Opcode
     * */
    private static byte[] generateOpcode(Opcode opcode) {
        byte[] rrq = {0, (byte) Opcode.RRQ.ordinal()}; // {0, 1}
        byte[] wrq = {0, (byte) Opcode.WRQ.ordinal()}; // {0, 2}
        byte[] data = {0, (byte) Opcode.DATA.ordinal()}; // {0, 3}
        byte[] ack = {0, (byte) Opcode.ACK.ordinal()}; // {0, 4}
        byte[] error = {0, (byte) Opcode.ERROR.ordinal()}; // {0, 5}
        byte[] none = {Byte.MIN_VALUE, Byte.MIN_VALUE}; // {-128, -128}

        switch (opcode) {
            case RRQ: return rrq;
            case WRQ: return wrq;
            case DATA: return data;
            case ACK: return ack;
            case ERROR: return error;
            default:
                System.err.println("ERROR 760: Opcode not recognized.");
                socket.close();
                System.exit(-1);
                return none;
        }
    }

    /**
     * Sends an acknowledgement packet (ACK) with the specified block number to
     * the server.
     *
     * @param block block number of DATA packet to be acknowledged.
     * @param serverPort port number of server.
     * @throws IOException if an I/O error occurs.
     * */
    private static void sendACK(int block, int serverPort) throws IOException {
        byte[] blockInBytes = fromIntToByte(block);
        byte[] packetContents = combineArr(generateOpcode(Opcode.ACK),
                blockInBytes);
        DatagramPacket ackToSend = new DatagramPacket(packetContents,
                packetContents.length);
        udtSend(ackToSend, serverPort, serverAddr);
    }

    /**
     * Concatenates two byte arrays in order and returns the result.
     *
     * @param array1 byte array to appear first.
     * @param array2 byte array to appear last.
     * @return concatenated result of array1 and array2 in that order.
     * */
    private static byte[] combineArr(byte[] array1, byte[] array2) {
        int aLen = array1.length;
        int bLen = array2.length;
        byte[] result = new byte[aLen + bLen];

        System.arraycopy(array1, 0, result, 0, aLen);
        System.arraycopy(array2, 0, result, aLen, bLen);
        return result;
    }

    /**
     * Converts the number stored in 2-tuple byte array base-256 into the
     * base-10 integer equivalent. b must be 2-tuple as b was initially
     * constructed in fromIntToByte(int) with checking mechanisms.
     * Block Number = (b[1] + 128) + 256 * (b[0] + 128), max = 65535.
     * {-128, -128} = 0
     * {-128, 0} = 128
     * {-128, 127} = 255
     * {-127, -128} = 256
     * {127, 127} = 65535
     *
     * @param b the byte array holding the 2-tuple base-256 bytes.
     * @return b in base-10 int format.
     * */
    private static int fromByteToInt(byte[] b) {
        int base = Byte.MAX_VALUE + (-1 * Byte.MIN_VALUE) + 1; // 256
        // ans = b[1] + 128 + 256 * (b[0] + 128)
        return (b[1] + (-1 * Byte.MIN_VALUE) + base * (b[0]
                + (-1 * Byte.MIN_VALUE)));
    }

    /**
     * Converts the number stored in integer base-10 format into a 2-tuple
     * Byte array, with both bytes in base-256 from min -128 to max 127.
     * Block Number = (b[1] + 128) + 256 * (b[0] + 128), max = 65535.
     * {-128, -128} = 0
     * {-128, 0} = 128
     * {-128, 127} = 255
     * {-127, -128} = 256
     * {127, 127} = 65535
     *
     * @param i number in base-10 integer format.
     * @return i in 2-tuple Byte array in base-256 (range of Byte) format.
     * Error if i is out of range (i < 0 or i > 65535).
     * */
    private static byte[] fromIntToByte(int i) throws IOException {
        int base = Byte.MAX_VALUE + (-1 * Byte.MIN_VALUE) + 1; // 256
        int max = base * (base - 1) + (base - 1); // 65535

        byte zerothDigit = (byte) (i / base + Byte.MIN_VALUE); // i / 256 - 128
        byte firstDigit = (byte) ((i % base) + Byte.MIN_VALUE); // i % 256 - 128

        if (i >= 0 && i <= max) {
            return new byte[]{zerothDigit, firstDigit};
        } else {
            System.out.println("ERROR 461: Block number out of range "
                    + "[0, 65535]. ");
            //slaveSocket.close();
            System.out.println("Terminating this server thread...");
            throw new IOException("ERROR 461 raised.\n");
        }
    }

    /**
     * Ensures a packet has the expected opcode. Returns true if the expected
     * opcode matches packet's opcode. False otherwise. Exits the system if a
     * packet's opcode is ERROR but the expected opcode is not ERROR, for
     * example, if a WRQ packet is responded with a FILE_NOT_FOUND error.
     *
     * @param recv packet whose opcode is to be compared.
     * @param op expected opcode.
     * @return true if packet's opcode is the expected opcode. False
     * otherwise. Exits the system if packet's opcode is ERROR when expected
     * opcode is not ERROR.
     * */
    private static boolean verifyPacketOpcode(DatagramPacket recv, Opcode op) {
        byte[] recvBuf = recv.getData();
        //System.out.println("length = " + recv.getLength() + "dwd" + recvBuf
        // .length);
        boolean isRRQ =
                ((generateOpcode(Opcode.RRQ)[1]) == recvBuf[1]);
        boolean isWRQ =
                ((generateOpcode(Opcode.WRQ)[1]) == recvBuf[1]);
        boolean isData =
                ((generateOpcode(Opcode.DATA)[1]) == recvBuf[1]);
        boolean isError =
                ((generateOpcode(Opcode.ERROR)[1]) == recvBuf[1]);
        boolean isAck =
                ((generateOpcode(Opcode.ACK)[1]) == recvBuf[1]);
        switch (op) {
            case RRQ:
                if (isRRQ) {
                    return true;
                }
                break;
            case WRQ:
                if (isWRQ) {
                    return true;
                }
                break;
            case DATA:
                if (isData) {
                    return true;
                }
                break;
            case ERROR:
                if (isError) {
                    int errorCode = recvBuf[3];
                    String dataReceived = new String(recvBuf);
                    String errMsg = dataReceived.substring(4,
                            recv.getLength() - 1);
                    System.out.println("ERROR 454: Expected error code "
                            + errorCode + " with message: " + errMsg);
                    System.out.println();
                    return true;
                }
                break;
            case ACK:
                if (isAck) {
                    return true;
                }
                break;
            default:
                System.out.println("ERROR 631: Unknown opcode of data "
                        + "received: " + recvBuf[1]);
                System.out.println();
                System.out.println("Terminating client...");
                socket.close();
                System.exit(-1);
        }
        if (isError) {
            int errorCode = recvBuf[3];
            String dataReceived = new String(recvBuf);
            try {
                String errMsg = dataReceived.substring(4, recv.getLength() - 1);
                System.out.println("ERROR 977: Unexpected error code 0"
                        + errorCode + " with message: " + errMsg + "\n");
            } catch (IndexOutOfBoundsException ioe) {
                System.out.println(ioe.getMessage() + "\n");
            }
            /*
            if (errorCode != Error.UNKNOWN_TID.ordinal()) {
                System.out.println("Terminating client...\n\n"
                        + "Client terminated.");
                socket.close();
                System.exit(-1);
            }*/
        }
        return false;
    }

    /**
     * Generates a DatagramPacket DATA packet with the given input contents of
     * the packet, with length equalling the actual used space which may be
     * 516 bytes (DEFAULT_DATA_SIZE + 4) or lower to a minimum of 4 bytes.
     *
     * @param readBuf character buffer of the DATA contents.
     * @param readCount number of characters in character buffer.
     * @param blockNumber block number of this DATA packet.
     * @return DATA packet with contents and block number.
     * */
    private static DatagramPacket produceDataPacket(char[] readBuf,
                                                    int readCount,
                                                    int blockNumber)
            throws IOException {
        byte[] dataBuf = new byte[DEFAULT_DATA_SIZE];

        // if only reading less than 512 chars, the read contents will be
        // the last content of the file. dataBuf readjusted to reflect final
        // content length
        if (readCount < DEFAULT_DATA_SIZE) {
            dataBuf = new byte[readCount];
        }

        // copying readBuf into dataBuf
        for (int i = 0; i < readCount; i++) {
            dataBuf[i] = (byte) readBuf[i];
        }

        // generating opcode for DATA
        byte[] dataOpcode = generateOpcode(Opcode.DATA);

        // generating block number in byte[] form
        byte[] block = fromIntToByte(blockNumber);

        // dataBuf = opcode + block number + data(original dataBuf)
        byte[] opcodeAndBlock = combineArr(dataOpcode, block);
        dataBuf = combineArr(opcodeAndBlock, dataBuf);

        // produce the DatagramPacket
        return new DatagramPacket(dataBuf, dataBuf.length);
    }

    /**
     * Sends a DatagramPacket to the given port and internet address.
     *
     * @param packet packet to be sent.
     * @param port port number of destination remote host.
     * @param addr internet address of destination remote host.
     * */
    private static void udtSend(DatagramPacket packet, int port,
                                InetAddress addr) throws IOException {
        packet.setAddress(addr);
        packet.setPort(port);

        // unnecessary random variable to invoke lost packet simulations
        double random = Math.random();
        if (random < (1 - LOST_PROBABILITY)) {
            socket.send(packet);
        } else {
            System.out.println("Packet made lost.");
        }
    }

    /**
     * Generates either a write request (WRQ) packet or read request (RRQ)
     * packet filled with a filename. Packet is without a predefined address or
     * port number.
     *
     * @param opcode opcode of operation, whether WRQ or RRQ.
     * @param filename name of file to be read or written.
     * @return WRQ or RRQ for file in question without address or port number.
     * */
    private static DatagramPacket generateRequestPacket(Opcode opcode,
                                                        String filename) {
        byte[] opcodeInByte = {Byte.MIN_VALUE, Byte.MIN_VALUE};
        if (opcode == Opcode.RRQ) {
            // getting opcode
            opcodeInByte = generateOpcode(Opcode.RRQ);
        } else if (opcode == Opcode.WRQ) {
            // getting opcode
            opcodeInByte = generateOpcode(Opcode.WRQ);
        } else {
            System.out.println("ERROR 005: Opcode is not RRQ or WRQ.");
            socket.close();
            System.exit(-1);
        }

        // getting mode, here remaining as octet
        String mode = "octet";

        // producing RRQ
        byte[] firstContentInBytes = combineArr(opcodeInByte,
                filename.getBytes());
        byte[] zero = {0};
        byte[] secondContentInBytes = combineArr(firstContentInBytes, zero);
        byte[] thirdContentInBytes = combineArr(secondContentInBytes,
                mode.getBytes());
        byte[] finalContentInBytes = combineArr(thirdContentInBytes, zero);
        return new DatagramPacket(finalContentInBytes,
                finalContentInBytes.length);
    }

    /**
     * A blocking call to receive an acknowledgement packet (ACK). If an ACK
     * with the expected block number is not received, the packet in line is
     * resent. If non-ACK packet received, this method remains open and
     * blocking until an ACK is received.
     *
     * Timeout is not initiated or handled here.
     *
     * @param expectedAck expected block number of incoming ACK.
     * @param packetInLine packet to be sent if the expected ACK is not
     *                     received.
     * @return received acknowledgement packet.
     * */
    private static DatagramPacket receiveAck(int expectedAck,
                                      DatagramPacket packetInLine)
            throws IOException {

        // receive the packet
        byte[] bufACK = new byte[4];
        DatagramPacket ackPacket = new DatagramPacket(bufACK, bufACK.length);

        // receive and verify opcode is ACK and coming from right server port
        // WRQ packets are always sent from a new port, so no need to check
        // the ports of any ACK 0's
        boolean isWRQ = verifyPacketOpcode(packetInLine, Opcode.WRQ);
        if (isWRQ) {
            socket.receive(ackPacket);
        } else {
            do {
                socket.receive(ackPacket);
            } while (!verifySocAddr(ackPacket, packetInLine.getPort(),
                    packetInLine.getAddress()));
        }
        verifyPacketOpcode(ackPacket, Opcode.ACK);

        // fixing serverPort
        int serverPort = packetInLine.getPort();

        // verifying expected ACK block number
        byte[] blockReceived = {bufACK[2], bufACK[3]};
        int ackReceived = fromByteToInt(blockReceived);
        if (ackReceived < expectedAck) {
            System.out.println("NOTE 002: ackReceived " + ackReceived
                    + " < expectedAck " + expectedAck
                    + ". DATA lost in network. ");
            udtSend(packetInLine, serverPort, serverAddr);
        } else if (ackReceived == expectedAck) {
            if (ackReceived == 0) {
                // indicates acknowledgement from server for a write request, no
                // need to check if packetInLine is less than 516 bytes
                System.out.println("Data block " + ackReceived
                        + " successfully acknowledged. Sending the file.\n");
                return ackPacket;
            }
            if (packetInLine.getLength() < DEFAULT_DATA_SIZE + 4) {
                System.out.println("Final data block " + ackReceived
                        + " successfully acknowledged. Terminating client.\n");
            } else {
                System.out.println("Data block " + ackReceived
                        + " successfully acknowledged. Sending next block.\n");
            }
        } else {
            System.out.println("ERROR 004: ackReceived " + ackReceived
                    + " > expectedAck " + expectedAck + ".");
            socket.close();
            System.exit(-1);
        }
        return ackPacket;
    }

    /**
     * Sends an ERROR packet to the sender upon receipt of unexpected packet
     * or a request which cannot be fulfilled including because of a
     * file-not-found error. Terminates (exits) client where necessary. Error
     * codes are based on RFC 1350.
     *
     * @param op error code of this error.
     * @param received packet received which raised this error.
     * @throws IOException if an I/O error occurs.
     * @see Error
     * */
    private static void sendErrorPacket(Error op, DatagramPacket received)
            throws IOException {
        byte[] opcode = generateOpcode(Opcode.ERROR);
        byte[] errCode = {Byte.MIN_VALUE, Byte.MIN_VALUE};
        byte[] errMsg;
        byte[] zero = {0};
        String message;
        boolean terminate = false;

        switch (op) {
            case NOT_DEFINED:
                // {0, 0}
                errCode = new byte[]{0, (byte) Error.NOT_DEFINED.ordinal()};
                message = "Not defined.";
                terminate = true;
                break;
            case FILE_NOT_FOUND:
                // {0, 1}
                errCode = new byte[]{0, (byte) Error.FILE_NOT_FOUND.ordinal()};
                String nameOfFile = getFilename(received.getData());
                message = "File " + nameOfFile + " not found.";
                terminate = true;
                break;
            case ACCESS_VIOLATION:
                // {0, 2}
                errCode = new byte[]{0, (byte) Error.ACCESS_VIOLATION
                        .ordinal()};
                message = "Access Violation.";
                terminate = true;
                break;
            case DISK_FULL:
                // {0, 3}
                errCode = new byte[]{0, (byte) Error.DISK_FULL.ordinal()};
                message = "Disk full or allocation exceeded.";
                terminate = true;
                break;
            case ILLEGAL_OPERATION:
                // {0, 4}
                errCode = new byte[]{0, (byte) Error.ILLEGAL_OPERATION
                        .ordinal()};
                message = "Illegal TFTP operation. Expecting a Write Request "
                        + "or Read Request.";
                terminate = true;
                break;
            case UNKNOWN_TID:
                // {0, 5}
                errCode = new byte[]{0, (byte) Error.UNKNOWN_TID.ordinal()};
                message = "Unknown Transfer ID. This connection is already "
                        + "used.";
                // only one where terminate = false
                break;
            case FILE_ALREADY_EXISTS:
                // {0, 6}
                errCode = new byte[]{0, (byte) Error.FILE_ALREADY_EXISTS
                        .ordinal()};
                message = "File already exists.";
                terminate = true;
                break;
            case NO_SUCH_USER:
                // {0, 7}
                errCode = new byte[]{0, (byte) Error.NO_SUCH_USER.ordinal()};
                message = "Mo such user.";
                terminate = true;
                break;
            default:
                message = "Not defined.";
                System.out.println("ERROR 993: Unknown Error Opcode.");
                terminate = true;
        }

        errMsg = (message).getBytes();
        System.out.println("ERROR 0" + errCode[1] + ": " + message + "\n");

        byte[] first = combineArr(opcode, errCode);
        byte[] second = combineArr(first, errMsg);
        byte[] third = combineArr(second, zero);

        DatagramPacket packet = new DatagramPacket(third, third.length);
        udtSend(packet, received.getPort(), received.getAddress());

        if (terminate) {
            System.out.println("Terminating client...\n Client terminated.");
            socket.close();
            System.exit(-1);
        }
    }

    /**
     * Verifies the source socket internet address of a received packet
     * is equal to the expected socket internet address (both port number and
     * internet address). Returns true if packet being checked is a response
     * to a WRQ since the source of ACK 0 is always a different port number
     * than port 69. Sends an ERROR to the source if returns false.
     *
     * @param received received packet.
     * @param port expected port number.
     * @param addr expected internet address.
     * @return true if received's port and internet address is equal to
     * expected port and address (or if received is ACK 0 to a WRQ). False
     * otherwise.
     * @throws IOException if an I/O error occurs.
     * */
    private static boolean verifySocAddr(DatagramPacket received, int port,
                                      InetAddress addr)
            throws IOException {
        boolean isWRQ = verifyPacketOpcode(received, Opcode.WRQ);
        if (isWRQ) {
            return true;
        } else {
            if (received.getPort() != port || !received.getAddress()
                    .equals(addr)) {
                sendConnectionUsedError(received);
                return false;
            } else {
                return true;
            }
        }
    }

    /**
     * Gets the filename from a write request (WRQ) or read request (RRQ).
     * Exits system if mode is not octet (and indirectly if the packet's
     * contents do not resemble that of a WRQ or RRQ).
     *
     * @param packetContents raw content of received WRQ or RRQ.
     * @return filename kept inside the WRQ or RRQ.
     * */
    private static String getFilename(byte[] packetContents) {

        // getting the locations of the three zero bytes
        // filename is located in index 2 : 2nd zero
        // mode is located in index (2nd zero + 1) : 3rd zero
        // per RFC: | 01/02 | Filename | 0 | Mode | 0 |
        int index2ndZero = 0;
        int index3rdZero = 0;
        int index = 0;
        for (byte b : packetContents) {
            if (index > 0) {
                if (b == 0) {
                    if (index2ndZero == 0) {
                        index2ndZero = index;
                    } else {
                        index3rdZero = index;
                        break;
                    }
                }
            }
            index++;
        }

        String filename = (new String(packetContents)).substring(2,
                index2ndZero);
        System.out.println("File in request is " + filename + ".");
        System.out.println();

        // ensuring mode is octet
        String octet =
                (new String(packetContents)).substring((index2ndZero + 1),
                        index3rdZero);
        if (!octet.equals("octet")) {
            System.out.println("ERROR 522: mode is not octet.");
            socket.close();
            System.exit(-1);
        }

        return filename;
    }

    /**
     * Sends an ERROR packet with an Unknown-TID error message. Used if a
     * packet is unexpectedly received from an unknown source. ERROR packet
     * is only sent once as courtesy and no acknowledgement is expected.
     *
     * @param received unexpectedly received alien packet.
     * @throws IOException if an I/O error occurs.
     */
    private static void sendConnectionUsedError(DatagramPacket received)
            throws IOException {
        sendErrorPacket(Error.UNKNOWN_TID, received);
    }

    /**
     * Generates and sends a write request (WRQ) packet repeatedly until the
     * initial acknowledgement (ACK with block number 0) is received, or if
     * this loops over CLIENT_BRAKE times.
     *
     * @param filename name of file to be written.
     * @return slave port number of remote server for subsequent transmissions.
     * @throws IOException if an I/O error occurs.
     * */
    private static int sendWRQ(String filename) throws IOException {
        DatagramPacket wrqPacket = generateRequestPacket(Opcode.WRQ, filename);

        int serverPort;
        int accessServerCount = 0;
        socket.setSoTimeout(TIMEOUT);

        while (true) {
            try {
                udtSend(wrqPacket, DEFAULT_SERVER_PORT, serverAddr);
                DatagramPacket receivedAck = receiveAck(0, wrqPacket);
                serverPort = (receivedAck).getPort();
                System.out.println("Connection established with TID/port "
                        + serverPort + ".");
                //socket.connect(receivedAck.getAddress(), serverPort);
                return serverPort;
            } catch (SocketTimeoutException soe) {
                if (accessServerCount > CLIENT_BRAKE) {
                    System.out.println("\nServer not responding. Terminating "
                            + "client...\n\nClient terminated.");
                    socket.close();
                    System.exit(-1);
                }
                System.out.println("NOTE 134: Timeout. Resending WRQ take "
                        + accessServerCount + ".");
            }
            accessServerCount++;
        }
    }


    // END OF FILE
}
