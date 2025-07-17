"""
Advanced GUI Timeline Plotter
-----------------------------
A tkinter GUI with calendar pickers for plotting event timelines with accurate dates.

Dependencies:
    pip install matplotlib numpy tkcalendar
"""

import tkinter as tk
from tkinter import ttk, messagebox
from tkcalendar import DateEntry
import matplotlib.pyplot as plt
import numpy as np
import datetime
import random

# --- Data Structures ---
categories = {}  # { category: [event_dict, ...] }
category_list = []

events = []  # List of all events

def random_colour():
    return "#" + ''.join([random.choice('0123456789ABCDEF') for _ in range(6)])

# --- GUI Setup ---
root = tk.Tk()
root.title("Advanced Timeline Plotter")
root.geometry("650x470")

frame = ttk.Frame(root, padding=12)
frame.pack(fill=tk.BOTH, expand=True)

# --- Category / Stage ---
ttk.Label(frame, text="Stage / Category:").grid(row=0, column=0, sticky="w")
category_var = tk.StringVar()
category_combo = ttk.Combobox(frame, textvariable=category_var, width=28)
category_combo['values'] = []
category_combo.grid(row=0, column=1, sticky="w")
ttk.Button(frame, text="New", width=5, command=lambda: add_new_category()).grid(row=0, column=2, padx=3)

def add_new_category():
    newcat = tk.simpledialog.askstring("New Category", "Enter new category name:")
    if newcat:
        category_list.append(newcat)
        category_combo['values'] = category_list
        category_var.set(newcat)

# --- Label ---
ttk.Label(frame, text="Label (short):").grid(row=1, column=0, sticky="w")
label_var = tk.StringVar()
label_entry = ttk.Entry(frame, textvariable=label_var, width=30)
label_entry.grid(row=1, column=1, sticky="w", columnspan=2)

# --- Date Type ---
date_type_var = tk.StringVar(value="single")
def date_type_toggle():
    if date_type_var.get() == "single":
        end_date_entry.grid_remove()
    else:
        end_date_entry.grid(row=3, column=1, sticky="w", padx=(145, 0))

ttk.Label(frame, text="Date type:").grid(row=2, column=0, sticky="w")
ttk.Radiobutton(frame, text="Single date", variable=date_type_var, value="single", command=date_type_toggle).grid(row=2, column=1, sticky="w")
ttk.Radiobutton(frame, text="Date range", variable=date_type_var, value="range", command=date_type_toggle).grid(row=2, column=1, sticky="w", padx=(120,0))

# --- Date pickers ---
ttk.Label(frame, text="Start date:").grid(row=3, column=0, sticky="w")
start_date_entry = DateEntry(frame, date_pattern="yyyy-mm-dd", width=12)
start_date_entry.grid(row=3, column=1, sticky="w")

ttk.Label(frame, text="End date:").grid(row=3, column=1, sticky="w", padx=(145,0))
end_date_entry = DateEntry(frame, date_pattern="yyyy-mm-dd", width=12)
end_date_entry.grid(row=3, column=1, sticky="w", padx=(215,0))
end_date_entry.grid_remove()

date_type_toggle()  # Set initial visibility

# --- Description ---
ttk.Label(frame, text="Description:").grid(row=4, column=0, sticky="nw")
description_text = tk.Text(frame, height=3, width=45, wrap=tk.WORD)
description_text.grid(row=4, column=1, columnspan=2, sticky="w")

# --- Listbox for events ---
ttk.Label(frame, text="Events in timeline:").grid(row=5, column=0, sticky="nw", pady=(12,0))
events_box = tk.Listbox(frame, width=80, height=7)
events_box.grid(row=5, column=1, columnspan=2, pady=(12,0))

# --- Add Event ---
def add_event():
    cat = category_var.get().strip()
    if not cat:
        messagebox.showwarning("Missing Data", "Please select or create a category.")
        return
    lab = label_var.get().strip()
    desc = description_text.get("1.0", tk.END).strip()
    if date_type_var.get() == "single":
        sdate = start_date_entry.get_date()
        edate = sdate
    else:
        sdate = start_date_entry.get_date()
        edate = end_date_entry.get_date()
        if edate < sdate:
            messagebox.showerror("Invalid Date", "End date cannot be before start date.")
            return
    if not (lab and desc):
        messagebox.showwarning("Missing Data", "Please fill in all fields.")
        return
    event = {
        "category": cat,
        "label": lab,
        "start": sdate,
        "end": edate,
        "description": desc
    }
    events.append(event)
    if cat not in categories:
        categories[cat] = []
        category_list.append(cat)
        category_combo['values'] = category_list
    categories[cat].append(event)
    # Display in listbox
    events_box.insert(tk.END, f"{cat}: '{lab}' ({sdate:%Y-%m-%d}{' to ' + edate.strftime('%Y-%m-%d') if sdate != edate else ''})")
    # Reset form
    label_var.set("")
    description_text.delete("1.0", tk.END)
    label_entry.focus()

ttk.Button(frame, text="Add Event", command=add_event).grid(row=6, column=1, pady=(7,0), sticky="w")

# --- Remove Selected Event ---
def remove_event():
    sel = events_box.curselection()
    if not sel:
        return
    idx = sel[0]
    # Remove from data structures
    ev = events.pop(idx)
    categories[ev['category']].remove(ev)
    if not categories[ev['category']]:
        del categories[ev['category']]
        category_list.remove(ev['category'])
        category_combo['values'] = category_list
    events_box.delete(idx)

ttk.Button(frame, text="Remove Selected", command=remove_event).grid(row=6, column=2, pady=(7,0), sticky="w")

# --- Plot Timeline ---
def plot_timeline():
    if not events:
        messagebox.showwarning("No Data", "No events to plot!")
        return

    # Colour by category
    category_colours = {cat: random_colour() for cat in categories}
    # Sort categories for consistent y positions
    sorted_categories = list(categories.keys())
    fig, ax = plt.subplots(figsize=(10, 6))
    y_pos = 0

    for category in sorted_categories:
        pins = categories[category]
        pins = sorted(pins, key=lambda x: (x["start"], x["end"]))
        ax.annotate(category, xy=(pins[0]["start"], y_pos + 0.18), fontsize=12, fontweight="bold", color=category_colours[category])
        for item in pins:
            ax.plot([item["start"], item["end"]], [y_pos, y_pos], color=category_colours[category], lw=7, solid_capstyle="butt")
            ax.annotate(item["label"], xy=(item["start"], y_pos), fontsize=10, ha="left", va="center")
            ax.annotate(item["description"], xy=(item["start"], y_pos), xytext=(10, 0), textcoords="offset points", fontsize=8, ha="left", va="center")
        y_pos += 1

    # Prepare x-ticks and y-ticks
    all_dates = []
    for ev in events:
        all_dates.append(ev["start"])
        if ev["start"] != ev["end"]:
            all_dates.append(ev["end"])
    all_dates = sorted(set(all_dates))
    ax.set_xticks(all_dates)
    ax.set_xticklabels([d.strftime("%Y-%m-%d") for d in all_dates], fontsize=10, rotation=45, ha="right")
    ax.set_yticks(np.arange(len(sorted_categories)))
    ax.set_yticklabels(sorted_categories, fontsize=12)
    ax.grid(axis="x", linestyle="--", color="gray")
    plt.title("Custom Timeline", fontsize=16, fontweight="bold")
    plt.tight_layout()
    plt.savefig("timeline.png")
    plt.show()
    messagebox.showinfo("Saved", "Timeline image saved as timeline.png in the current folder.")

ttk.Button(frame, text="Finish and Plot", command=plot_timeline).grid(row=7, column=1, pady=(12,0), sticky="w")

root.mainloop()
