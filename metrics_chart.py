import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# Precision Chart (Thermometer/Progress Bar Style) 
precision_value = 1.00

fig, ax = plt.subplots(figsize=(4, 7))

# Background bar (grey - represents max possible)
ax.barh([0], [1.0], color='#eeeeee', height=0.5, edgecolor='grey', linewidth=1)

# Foreground bar (blue - represents actual score)
ax.barh([0], [precision_value], color='steelblue', height=0.5)

# Score label inside the bar
ax.text(precision_value / 2, 0, f'{precision_value:.2f}',
        ha='center', va='center', fontsize=20,
        fontweight='bold', color='white')

# Axis formatting
ax.set_xlim(0, 1.2)
ax.set_ylim(-0.5, 0.5)
ax.set_xticks([0, 0.25, 0.50, 0.75, 1.00])
ax.set_xticklabels(['0', '0.25', '0.50', '0.75', '1.00'], fontsize=10)
ax.set_yticks([])
ax.axvline(x=1.0, color='green', linestyle='--', linewidth=1.5, label='Perfect Score (1.00)')
ax.set_title('IDS Precision Score', fontsize=14, fontweight='bold', pad=15)
ax.legend(loc='upper right', fontsize=9)
plt.tight_layout()
plt.savefig('precision_chart.png', dpi=150)
plt.show()

# Recall Chart (Pie Chart)
recall_value = 1.00

fig, ax = plt.subplots(figsize=(6, 6))
sizes = [recall_value, 1 - recall_value] if recall_value < 1 else [1.00, 0.001]
labels = ['Detected (Recall)', '']
colors = ['darkorange', '#eeeeee']
explode = (0.05, 0)
wedges, texts, autotexts = ax.pie(
    sizes,
    labels=labels,
    colors=colors,
    explode=explode,
    autopct=lambda p: f'{recall_value*100:.0f}%' if p > 50 else '',
    startangle=90,
    textprops={'fontsize': 13}
)
autotexts[0].set_fontsize(15)
autotexts[0].set_fontweight('bold')
ax.set_title('IDS Recall Score', fontsize=14)
plt.tight_layout()
plt.savefig('recall_chart.png', dpi=150)
plt.show()

# F1 Score Chart (Gauge Style)
f1_value = 1.00

fig, ax = plt.subplots(figsize=(7, 4), subplot_kw={'projection': 'polar'})
ax.set_theta_offset(np.pi)
ax.set_theta_direction(-1)
ax.set_thetamin(0)
ax.set_thetamax(180)

# Background arc (grey)
theta_bg = np.linspace(0, np.pi, 200)
ax.fill_between(theta_bg, 0.7, 1.0, color='lightgrey', alpha=0.5)

# Score arc (green)
theta_score = np.linspace(0, np.pi * f1_value, 200)
ax.fill_between(theta_score, 0.7, 1.0, color='mediumseagreen', alpha=0.9)

# Needle
needle_angle = np.pi * f1_value
ax.annotate('', xy=(needle_angle, 0.9), xytext=(needle_angle, 0.5),
            arrowprops=dict(arrowstyle='->', color='black', lw=2))

ax.set_yticklabels([])
ax.set_xticks([0, np.pi/4, np.pi/2, 3*np.pi/4, np.pi])
ax.set_xticklabels(['0', '0.25', '0.50', '0.75', '1.00'], fontsize=10)
ax.set_title(f'IDS F1 Score: {f1_value:.2f}', fontsize=14, pad=20)
ax.grid(False)
plt.tight_layout()
plt.savefig('f1_score_chart.png', dpi=150)
plt.show()

# Accuracy Chart (TP and TN Breakdown Bar)
tp = 1   # True Positives
tn = 35  # True Negatives (unique legitimate APs correctly ignored)
fp = 0   # False Positives
fn = 0   # False Negatives

fig, ax = plt.subplots(figsize=(7, 5))
categories = ['True Positives\n(Rogue AP Detected)', 'True Negatives\n(Legit APs Ignored)', 'False Positives\n(Wrong Alerts)', 'False Negatives\n(Missed Rogues)']
values = [tp, tn, fp, fn]
colors = ['mediumseagreen', 'steelblue', 'tomato', 'orange']
bars = ax.bar(categories, values, color=colors, width=0.5)
ax.set_ylabel('Count')
ax.set_title(f'IDS Accuracy Breakdown (Accuracy: 1.00)')
ax.bar_label(bars, padding=5, fontsize=12)
ax.set_ylim(0, max(values) + 5)
plt.xticks(fontsize=9)
plt.tight_layout()
plt.savefig('accuracy_chart.png', dpi=150)
plt.show()