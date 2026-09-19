"""Rebuild the original strategy charts from included CSV data."""
from pathlib import Path
import csv
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
R=Path(__file__).resolve().parents[1]
A=R/'assets'
def save(fig,name):
 fig.tight_layout()
 for ext in ('png','svg'):fig.savefig(A/(name+'.'+ext),dpi=200)
 plt.close(fig)
with (A/'market_context.csv').open() as f:rows=list(csv.DictReader(f))
x=list(range(len(rows)));total=[float(v['total_usd_trillion']) for v in rows];infra=[float(v['infrastructure_usd_trillion']) for v in rows]
fig,ax=plt.subplots(figsize=(9,4.8));ax.bar(x,infra,width=.56,label='AI infrastructure');ax.bar(x,[a-b for a,b in zip(total,infra)],bottom=infra,width=.56,label='Other AI spending')
ax.set_xticks(x,[v['period'] for v in rows]);ax.set_ylabel('Annual worldwide spending · US$ trillion');ax.set_title('A capital-scale market',pad=16)
for i,v in enumerate(total):ax.text(i,v+.06,f'${v:.2f}tn',ha='center')
ax.set_ylim(0,4.2);ax.spines[['top','right']].set_visible(False);ax.legend(frameon=False,loc='upper left');save(fig,'market_context')
with (A/'ownership_curve.csv').open() as f:rows=list(csv.DictReader(f))
x=[float(v['annual_tasks_million']) for v in rows];a=[float(v['service_three_year_usd'])/1000 for v in rows];b=[float(v['local_three_year_usd'])/1000 for v in rows]
fig,ax=plt.subplots(figsize=(9,4.8));ax.plot(x,a,linewidth=2.4,label='Remote service');ax.plot(x,b,linewidth=2.4,label='Local capability');be=245000/.03/1000000;ax.axvline(be,linestyle='--',linewidth=1);ax.annotate(f'Break-even: {be:.2f}m accepted tasks/year',xy=(be,245),xytext=(10,100),arrowprops={'arrowstyle':'->'})
ax.set_xlabel('Annual accepted tasks · millions');ax.set_ylabel('Three-year cash cost · US$ thousands');ax.set_title('Repetition changes the capital decision',pad=16);ax.legend(frameon=False,loc='upper left');ax.spines[['top','right']].set_visible(False);save(fig,'ownership_curve')
fig,ax=plt.subplots(figsize=(9,4.8));values=[3,2,5];bottoms=[0,3,0];ax.bar(['Internal reallocation','External net inflow','New strategy assets'],values,bottom=bottoms,width=.55)
for i,(v,b) in enumerate(zip(values,bottoms)):ax.text(i,b+v+.1,f'${v:.0f}bn',ha='center')
ax.set_ylim(0,6);ax.set_ylabel('Illustrative assets · US$ billion');ax.set_title(r'A \$5bn product can add \$2bn of net new firm assets',pad=16);ax.spines[['top','right']].set_visible(False);save(fig,'asset_growth_bridge')
print('Rebuilt three original charts.')
