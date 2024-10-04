# cryptography-blockchain
# Blockchain and Transactions in Python

This project implements a simple blockchain that handles transactions and displays them in a graphical user interface (GUI) and on the console.

## Overview

- **Block Class**: Represents a block in the blockchain, containing an index, previous hash, Merkle root, transactions, nonce, timestamp, and hash.
- **Merkle Root Function**: Recursively calculates the Merkle root of the transactions.
- **Transaction Class**: Represents a transaction with sender, recipient, amount, sender's balance after the transaction, recipient's balance after the transaction, and a digital signature.
- **Blockchain Class**: Manages the blockchain, including creating the genesis block, adding new blocks, performing proof of work, creating accounts, and processing transactions.
- **RSA Key Pair Generation**: Generates an RSA key pair for signing transactions.
- **ScrollableFrame Class**: Creates a scrollable frame in the GUI.
- **display_blockchain Function**: Displays the blockchain in the GUI and prints it to the console.
- **add_block Function**: Adds a new block to the blockchain after processing a transaction.
- **open_add_block_window Function**: Opens a window to add a new block via the GUI.

## Key Features

- **Graphical User Interface (GUI)**: Uses Tkinter to create a user-friendly interface for interacting with the blockchain.
- **Console Output**: Prints blockchain details to the console for easy debugging and verification.
- **Digital Signatures**: Ensures transaction integrity and authenticity using RSA digital signatures.
- **Proof of Work**: Implements a simple proof of work algorithm to secure the blockchain.

This code provides a foundational understanding of how blockchains and transactions work, with a focus on simplicity and educational value.
