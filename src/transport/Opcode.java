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

/**
 * All available opcode of operations specified in RFC 1350.
 *
 * @author 223459 afd22@sussex.ac.uk
 * @version 1.0 %G%, %U%.
 * */
public enum Opcode {
    /** 0 Blank (do not use). Placed to ensure ordinals of other enums are
     * accurate. */
    BLANK,
    /** 1 Read request (RRQ). */
    RRQ,
    /** 2 Write request (WRQ). */
    WRQ,
    /** 3 Data (DATA). */
    DATA,
    /** 4 Acknowledgment (ACK). */
    ACK,
    /** 5 Error (ERROR). */
    ERROR

    /*
    * opcode  operation
            0     Blank (do not use)
            1     Read request (RRQ)
            2     Write request (WRQ)
            3     Data (DATA)
            4     Acknowledgment (ACK)
            5     Error (ERROR)
    * */
}
