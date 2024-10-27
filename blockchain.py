import hashlib
import json
import time
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import tkinter as tk
from tkinter import ttk

class Block:
    def __init__(self, index, previous_hash, merkle_root, transactions, nonce=0):
        self.index = index
        self.previous_hash = previous_hash
        self.merkle_root = merkle_root
        self.transactions = [t.__dict__ for t in transactions]  # Convert transactions to dict
        self.nonce = nonce
        self.timestamp = time.time()
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

def merkle_root(transactions):
    if len(transactions) == 1:
        return transactions
    
    new_level = []
    for i in range(0, len(transactions)-1, 2):
        new_level.append(hashlib.sha256((transactions[i] + transactions[i+1]).encode()).hexdigest())
    
    if len(transactions) % 2 == 1:
        new_level.append(hashlib.sha256((transactions[-1] + transactions[-1]).encode()).hexdigest())
    
    return merkle_root(new_level)

class Transaction:
    def __init__(self, sender, recipient, amount, private_key, sender_balance_after, recipient_balance_after):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.sender_balance_after = sender_balance_after
        self.recipient_balance_after = recipient_balance_after
        self.signature = self.sign_transaction(private_key)

    def sign_transaction(self, private_key):
        key = RSA.import_key(private_key)
        h = SHA256.new(f'{self.sender}{self.recipient}{self.amount}'.encode())
        return pkcs1_15.new(key).sign(h).hex()

class Blockchain:
    def __init__(self):
        self.chain = []
        self.accounts = {}
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, "0", "0", [], 0)
        self.chain.append(genesis_block)

    def add_block(self, new_block):
        new_block.previous_hash = self.chain[-1].hash
        self.chain.append(new_block)

    def proof_of_work(self, block, difficulty):
        while block.hash[:difficulty] != '0' * difficulty:
            block.nonce += 1
            block.hash = block.calculate_hash()
            print(f"Trying nonce: {block.nonce} | Hash: {block.hash}")  # Debug üzenet
        print(f"Proof of work completed with nonce: {block.nonce} | Hash: {block.hash}")
        return block.hash


    def create_account(self, user):
        if user not in self.accounts:
            self.accounts[user] = 500

    def process_transaction(self, transaction):
        sender = transaction.sender
        recipient = transaction.recipient
        amount = transaction.amount

        if self.accounts.get(sender, 0) >= amount:
            self.accounts[sender] -= amount
            self.accounts[recipient] = self.accounts.get(recipient, 0) + amount
            return True
        else:
            return False

# Blokklánc létrehozása
blockchain = Blockchain()
difficulty = 4

# RSA kulcspár generálása
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# Görgethető keret osztály
class ScrollableFrame(ttk.Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        canvas = tk.Canvas(self)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

# GUI létrehozása
def display_blockchain():
    for widget in scrollable_frame.scrollable_frame.winfo_children():
        widget.destroy()
    
    for block in blockchain.chain:
        block_info = (
            f"Index: {block.index}\n"
            f"Previous Hash: {block.previous_hash}\n"
            f"Merkle Root: {block.merkle_root}\n"
            f"Nonce: {block.nonce}\n"
            f"Hash: {block.hash}\n"
            f"Timestamp: {block.timestamp}\n"      
        )
        for tx in block.transactions:
            sender = tx['sender']
            recipient = tx['recipient']
            amount = tx['amount']
            sender_balance_after = tx['sender_balance_after']
            recipient_balance_after = tx['recipient_balance_after']
            signature = tx['signature']  # Signature hozzáadása
            block_info += (
                f"Sender: {sender}\n"
                f"Sender Balance After Transaction: {sender_balance_after}\n"
                f"Amount: {amount}\n"
                f"Recipient: {recipient}\n"
                f"Recipient Balance After Transaction: {recipient_balance_after}\n"
                f"Signature: {signature}\n" 
                "-------------------------\n"
            )
        text = tk.Text(scrollable_frame.scrollable_frame, wrap=tk.WORD, padx=10, pady=10, borderwidth=2, relief="groove")
        text.insert(tk.END, block_info)
        text.config(state=tk.DISABLED)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Konzolra írás
        print(block_info)

def add_block(sender, recipient, amount, add_block_window):
    if not sender or not recipient or not amount:
        return
    
    try:
        amount = float(amount)
    except ValueError:
        return
    
    blockchain.create_account(sender)
    blockchain.create_account(recipient)
    
    sender_balance_after = blockchain.accounts.get(sender, 0) - amount
    recipient_balance_after = blockchain.accounts.get(recipient, 0) + amount
    transaction = Transaction(sender, recipient, amount, private_key, sender_balance_after, recipient_balance_after)
    
    if blockchain.process_transaction(transaction):
        transactions = [transaction]
        new_block = Block(len(blockchain.chain), blockchain.chain[-1].hash, merkle_root([t.signature for t in transactions]), transactions)
        blockchain.proof_of_work(new_block, difficulty)
        blockchain.add_block(new_block)
        display_blockchain()
    else:
        error_label.config(text="Insufficient funds!")

def open_add_block_window():
    add_block_window = tk.Toplevel(root)
    add_block_window.title("Add Block")

    ttk.Label(add_block_window, text="Sender:").grid(column=0, row=0, sticky=tk.W)
    sender_entry = ttk.Entry(add_block_window, width=20)
    sender_entry.grid(column=1, row=0, sticky=(tk.W, tk.E))

    ttk.Label(add_block_window, text="Recipient:").grid(column=0, row=1, sticky=tk.W)
    recipient_entry = ttk.Entry(add_block_window, width=20)
    recipient_entry.grid(column=1, row=1, sticky=(tk.W, tk.E))

    ttk.Label(add_block_window, text="Amount:").grid(column=0, row=2, sticky=tk.W)
    amount_entry = ttk.Entry(add_block_window, width=20)
    amount_entry.grid(column=1, row=2, sticky=(tk.W, tk.E))

    def add_block_from_window():
        sender = sender_entry.get()
        recipient = recipient_entry.get()
        amount = amount_entry.get()
        add_block(sender, recipient, amount, add_block_window)

    add_button = ttk.Button(add_block_window, text="Add Block", command=add_block_from_window)
    add_button.grid(column=0, row=3, columnspan=2, pady=10)

root = tk.Tk()
root.title("Blockchain Viewer")

frame = ttk.Frame(root, padding="10")
frame.pack(fill=tk.BOTH, expand=True)

scrollable_frame = ScrollableFrame(frame)
scrollable_frame.pack(fill="both", expand=True)

form_frame = ttk.Frame(root, padding="10")
form_frame.pack(fill=tk.BOTH, expand=True)

display_button = ttk.Button(root, text="Display Blockchain", command=display_blockchain)
display_button.pack(pady=10)

add_block_button = ttk.Button(root, text="Open Add Block Window", command=open_add_block_window)
add_block_button.pack(pady=10)

error_label = ttk.Label(root, text="", foreground="red")
error_label.pack()

root.mainloop()
