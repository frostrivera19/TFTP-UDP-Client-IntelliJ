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
 * All available errors as specified in RFC 1350. Only FILE_NOT_FOUND is
 * properly calibrated in this project.
 *
 * @author 223459 afd22@sussex.ac.uk
 * @version 1.0 %G%, %U%.
 * */
public enum Error {
    /** 0 Not defined, see error message (if any). */
    NOT_DEFINED,
    /** 1 File not found. */
    FILE_NOT_FOUND,
    /** 2 Access violation. */
    ACCESS_VIOLATION,
    /** 3 Disk full or allocation exceeded. */
    DISK_FULL,
    /** 4 Illegal TFTP operation. */
    ILLEGAL_OPERATION,
    /** 5 Unknown transfer ID. */
    UNKNOWN_TID,
    /** 6 File already exists. */
    FILE_ALREADY_EXISTS,
    /** 7 No such user. */
    NO_SUCH_USER

    /*
    * Error Codes
        Value Meaning
        0 Not defined, see error message (if any).
        1 File not found.
        2 Access violation.
        3 Disk full or allocation exceeded.
        4 Illegal TFTP operation.
        5 Unknown transfer ID.
        6 File already exists.
        7 No such user.
        * In this assignment, only FILE_NOT_FOUND and UNKNOWN_TID is handled.
    * */
}
