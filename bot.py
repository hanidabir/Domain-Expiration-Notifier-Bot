#!/usr/bin/env python3
import asyncio, logging, os, re, sqlite3, smtplib, tempfile
from datetime import date, datetime, timezone
from email.message import EmailMessage
from pathlib import Path
import requests
from dotenv import load_dotenv
from telegram import Update, ReplyKeyboardMarkup, KeyboardButton, InlineKeyboardMarkup, InlineKeyboardButton
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters

load_dotenv()
WHOIS_EXCLUDE_SUFFIXES = ('.ir', '.de', '.eu', '.it', '.at', '.be', '.li', '.ch', '.fr', '.nl', '.no', '.hu', '.bg', '.gr', '.ai', '.sg', '.hr', '.is', '.jp', '.es', '.lu', '.za', '.si')
CHECK_INTERVAL = 7 * 24 * 60 * 60
TOKEN=os.getenv('TELEGRAM_BOT_TOKEN','').strip(); WHOAPI_KEY=os.getenv('WHOAPI_KEY','').strip()
DB_PATH=os.getenv('DB_PATH',str(Path(os.getenv('TEMP')) / 'domain-expiration-bot' / 'domains.sqlite3')); WARNING_DAYS=int(os.getenv('WARNING_DAYS','30'))
SMTP_HOST=os.getenv('SMTP_HOST','').strip(); SMTP_PORT=int(os.getenv('SMTP_PORT','587')); SMTP_USER=os.getenv('SMTP_USER','').strip(); SMTP_PASSWORD=os.getenv('SMTP_PASSWORD',''); SMTP_FROM=os.getenv('SMTP_FROM',SMTP_USER).strip(); SMTP_TLS=os.getenv('SMTP_USE_TLS','true').lower() in ('1','true','yes')
logging.basicConfig(level=os.getenv('LOG_LEVEL','INFO'),format='%(asctime)s %(levelname)s %(name)s: %(message)s'); log=logging.getLogger('domain-bot')
MENU=ReplyKeyboardMarkup([[KeyboardButton('➕ افزودن دامنه'),KeyboardButton('➖ حذف دامنه')],[KeyboardButton('📋 دامنه‌های من'),KeyboardButton('ℹ️ راهنما')]],resize_keyboard=True)
DELETE_MENU=ReplyKeyboardMarkup([[KeyboardButton('🗑 حذف موردی'),KeyboardButton('🔥 حذف همه')],[KeyboardButton('↩️ بازگشت به منو')]],resize_keyboard=True,one_time_keyboard=True)
def db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=20)
    c.row_factory = sqlite3.Row
    return c
def now(): return datetime.now(timezone.utc).isoformat(timespec='seconds')
def init_db():
 # Keep the writable SQLite database in Windows Temp, not beside the script.
 Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
 schema_file = Path(__file__).with_name('schema.sql')
 with db() as c:
  c.executescript(schema_file.read_text(encoding='utf-8'))
  for r in c.execute('SELECT id,expiration_date FROM domains').fetchall():
   try: c.execute('UPDATE domains SET days_left=? WHERE id=?',((date.fromisoformat(r['expiration_date'])-date.today()).days,r['id']))
   except ValueError: pass
def norm_domain(raw):
 d=re.sub(r'^https?://','',raw.strip().lower()).split('/')[0].split('?')[0].split('#')[0].rstrip('.')
 if ':' in d: d=d.split(':',1)[0]
 if d.startswith('www.'): d=d[4:]
 if len(d)>253 or '.' not in d or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in d.split('.')): raise ValueError('نام دامنه معتبر نیست.')
 return d
def valid_email(s): return bool(re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+',s.strip()))
def parse_date(s):
 for fmt in ('%Y-%m-%d','%Y/%m/%d','%d-%m-%Y','%d/%m/%Y'):
  try: return datetime.strptime(s.strip(),fmt).date().isoformat()
  except ValueError: pass
 raise ValueError('تاریخ را به شکل YYYY-MM-DD وارد کن؛ مثال: 2027-01-02')
def parse_date_lines(text,expected):
 found={}; errors=[]
 for line in text.splitlines():
  line=line.strip()
  if not line: continue
  if ':' not in line: errors.append(f'«{line}» — فرمت باید domain: YYYY-MM-DD باشد'); continue
  raw,dstr=line.rsplit(':',1)
  try:
   d=norm_domain(raw); exp=parse_date(dstr)
   if d not in expected: errors.append(f'«{d}» در فهرست دامنه‌های در انتظار ثبت نیست')
   else: found[d]=exp
  except ValueError as e: errors.append(f'«{line}» — {e}')
 missing=[d for d in expected if d not in found]
 if missing: errors.append('تاریخ وارد نشده برای: '+', '.join(missing))
 return found,errors
def whois_expiry(domain):
 if not WHOAPI_KEY: return None,'WHOAPI_KEY تنظیم نشده است'
 try:
  r=requests.get('https://api.whoapi.com/',params={'domain':domain,'r':'whois','apikey':WHOAPI_KEY},timeout=25); r.raise_for_status(); data=r.json(); raw=data.get('date_expires')
  if not raw: return None,data.get('status_desc') or data.get('error') or 'WhoAPI تاریخ انقضا برنگرداند'
  parsed=None
  for fmt in ('%Y-%m-%d %H:%M:%S','%Y-%m-%d','%Y-%m-%dT%H:%M:%S%z','%Y-%m-%dT%H:%M:%S','%d-%b-%Y','%d/%m/%Y'):
   try: parsed=datetime.strptime(str(raw).strip(),fmt); break
   except ValueError: pass
  if parsed is None:
   try: parsed=datetime.fromisoformat(str(raw).strip().replace('Z','+00:00'))
   except ValueError: return None,f'فرمت تاریخ ناشناخته: {raw}'
  return parsed.date().isoformat(),None
 except (requests.RequestException,ValueError) as e: return None,str(e)
def email_alert(to,owner,messages):
 if not all([SMTP_HOST,SMTP_USER,SMTP_PASSWORD,SMTP_FROM]): log.warning('SMTP not configured; skipped email to %s',to); return False
 msg=EmailMessage(); msg['Subject']='هشدار انقضای دامنه'; msg['From']=SMTP_FROM; msg['To']=to; msg.set_content(f'سلام {owner}،\n\n'+'\n\n'.join(messages))
 try:
  if SMTP_TLS:
   with smtplib.SMTP(SMTP_HOST,SMTP_PORT,timeout=25) as s: s.starttls(); s.login(SMTP_USER,SMTP_PASSWORD); s.send_message(msg)
  else:
   with smtplib.SMTP_SSL(SMTP_HOST,SMTP_PORT,timeout=25) as s: s.login(SMTP_USER,SMTP_PASSWORD); s.send_message(msg)
  return True
 except Exception: log.exception('Email delivery failed to %s',to); return False
def user_for(uid):
 with db() as c: return c.execute('SELECT * FROM users WHERE telegram_id=?',(uid,)).fetchone()
def domains_for(uid):
 with db() as c: return c.execute('SELECT * FROM domains WHERE telegram_id=? ORDER BY domain',(uid,)).fetchall()
async def reply(update,text,**kwargs):
 if update.effective_message: await update.effective_message.reply_text(text,**kwargs)
async def start(update:Update,ctx:ContextTypes.DEFAULT_TYPE):
 ctx.user_data.clear(); u=user_for(update.effective_user.id)
 await reply(update,(f"سلام {u['owner']}! چه کاری می‌خواهی انجام بدهی؟" if u else 'سلام! به ربات مدیریت انقضای دامنه خوش آمدی.\nبرای شروع از منو «➕ افزودن دامنه» را انتخاب کن.'),reply_markup=MENU)
async def help_cmd(update,ctx): await reply(update,'➕ افزودن دامنه: ثبت یک یا چند دامنه\n➖ حذف دامنه: حذف موردی یا همه\n📋 دامنه‌های من: نمایش فهرست و تاریخ‌ها\n\nتاریخ‌ها: YYYY-MM-DD\nبرای لغو هر مرحله /cancel را بفرست.',reply_markup=MENU)
async def begin_add(update,ctx):
 if not user_for(update.effective_user.id): ctx.user_data['state']='name'; await reply(update,'نام خود را وارد کنید:')
 else: ctx.user_data['state']='domains'; await reply(update,'دامنه‌های خود را وارد کنید. اگر چند دامنه دارید، در هر خط یک دامنه بنویسید.\nمثال:\nexample.com\nsite.com')
async def show_domains(update,ctx):
 rows=domains_for(update.effective_user.id)
 if not rows: await reply(update,'هنوز دامنه‌ای ثبت نکرده‌ای.',reply_markup=MENU); return
 lines=[f"• {r['domain']} — {r['expiration_date']} ({(date.fromisoformat(r['expiration_date'])-date.today()).days} روز باقی‌مانده)" for r in rows]
 await reply(update,'دامنه‌های ثبت‌شده:\n\n'+'\n'.join(lines),reply_markup=MENU)
async def begin_delete(update,ctx):
 if not user_for(update.effective_user.id): await reply(update,'ابتدا اطلاعاتت را با گزینه افزودن دامنه ثبت کن.',reply_markup=MENU); return
 ctx.user_data['state']='delete_menu'; await reply(update,'کدام روش حذف را می‌خواهی؟',reply_markup=DELETE_MENU)
def save_domain_expiries(uid, ctx, mapping):
    u = user_for(uid)
    owner = u['owner'] if u else ctx.user_data.get('owner', '')
    email = u['email'] if u else ctx.user_data.get('email', '')

    with db() as c:
        if not u:
            c.execute(
                'INSERT INTO users(telegram_id,owner,email,created_at,updated_at) '
                'VALUES(?,?,?,?,?)',
                (uid, owner, email, now(), now())
            )

        for d, exp in mapping.items():
            days = (date.fromisoformat(exp) - date.today()).days
            c.execute(
                'INSERT INTO domains(telegram_id,domain,expiration_date,days_left,added_at,updated_at) '
                'VALUES(?,?,?,?,?,?) '
                'ON CONFLICT(telegram_id,domain) DO UPDATE SET '
                'expiration_date=excluded.expiration_date, '
                'days_left=excluded.days_left, updated_at=excluded.updated_at',
                (uid, d, exp, days, now(), now())
            )
async def text_handler(update:Update,ctx:ContextTypes.DEFAULT_TYPE):
 text=(update.effective_message.text or '').strip(); uid=update.effective_user.id; state=ctx.user_data.get('state')
 if text in ('/cancel','↩️ بازگشت به منو'):
  ctx.user_data.clear(); await reply(update,'به منوی اصلی برگشتی.',reply_markup=MENU); return
 if text=='ℹ️ راهنما': await help_cmd(update,ctx); return
 if text=='➕ افزودن دامنه': await begin_add(update,ctx); return
 if text=='📋 دامنه‌های من': await show_domains(update,ctx); return
 if text=='➖ حذف دامنه': await begin_delete(update,ctx); return
 if state=='name':
  if not 2<=len(text)<=100: await reply(update,'لطفا نامی معتبر بین ۲ تا ۱۰۰ نویسه وارد کن:'); return
  ctx.user_data['owner']=text; ctx.user_data['state']='email'; await reply(update,'آدرس ایمیل خود را وارد کنید:'); return
 if state=='email':
  if not valid_email(text): await reply(update,'ایمیل معتبر نیست؛ مثال: name@example.com'); return
  ctx.user_data['email']=text; ctx.user_data['state']='domains'; await reply(update,'دامنه‌های خود را وارد کنید. اگر چند دامنه دارید، در هر خط یک دامنه بنویسید.\nمثال:\nexample.com\nsite.com'); return
 if state=='domains':
  ds=[]; invalid=[]
  for raw in text.splitlines():
   if not raw.strip(): continue
   try:
    d=norm_domain(raw)
    if d not in ds: ds.append(d)
   except ValueError:
    invalid.append(raw.strip())

  if invalid:
   await reply(update,'این دامنه‌ها معتبر نیستند:\n'+'\n'.join(invalid))
   return

  if not ds:
   await reply(update,'دامنه‌ای دریافت نکردم؛ هر دامنه را در یک خط بفرست.')
   return

  existing={r['domain'] for r in domains_for(uid)}
  ds=[d for d in ds if d not in existing]

  if not ds:
   ctx.user_data.clear()
   await reply(update,'همه این دامنه‌ها از قبل ثبت شده‌اند.',reply_markup=MENU)
   return

  auto_expiries={}
  need_manual=[]

  await reply(update,'در حال بررسی تاریخ انقضای دامنه‌ها هستم...')

  for d in ds:
   if any(d.endswith(suffix) for suffix in WHOIS_EXCLUDE_SUFFIXES):
    need_manual.append(d)
    continue

   exp, error = await whois_async(d)

   if exp:
    auto_expiries[d]=exp
   else:
    need_manual.append(d)
    log.info('WHOIS expiry unavailable for %s: %s', d, error)

  ctx.user_data['auto_expiries']=auto_expiries
  ctx.user_data['pending_domains']=need_manual

  if need_manual:
   ctx.user_data['state']='dates'

   message=''
   if auto_expiries:
    message='تاریخ انقضای این دامنه‌ها دریافت شد:\n'
    message+='\n'.join(f'• {d}: {exp}' for d,exp in auto_expiries.items())
    message+='\n\n'

   message+='برای دامنه‌های زیر تاریخ انقضای میلادی را دستی وارد کن:\n'
   message+='هر دامنه در یک خط با فرمت domain: YYYY-MM-DD (سال-ماه-روز)\n\n'
   message+='\n'.join(f'{d}: YYYY-MM-DD' for d in need_manual)

   await reply(update,message)
   return

  save_domain_expiries(uid,ctx,auto_expiries)
  ctx.user_data.clear()

  await reply(
   update,
   '✅ دامنه‌ها و تاریخ انقضایشان ذخیره شدند:\n\n'
   +'\n'.join(f'• {d}: {exp}' for d,exp in auto_expiries.items()),
   reply_markup=MENU
  )
  return
 if state=='dates':
  ds=ctx.user_data.get('pending_domains',[])
  manual_mapping,errors=parse_date_lines(text,ds)

  if errors:
   await reply(
    update,
    'لطفا موارد زیر را اصلاح کن و همه تاریخ‌های لازم را دوباره بفرست:\n\n'
    +'\n'.join(errors)
    +'\n\nفرمت: example.com: 2027-01-02'
   )
   return

  mapping=ctx.user_data.get('auto_expiries',{}).copy()
  mapping.update(manual_mapping)

  save_domain_expiries(uid,ctx,mapping)
  ctx.user_data.clear()

  await reply(
   update,
   '✅ دامنه‌ها و تاریخ انقضایشان ذخیره شدند:\n\n'
   +'\n'.join(f'• {d}: {exp}' for d,exp in mapping.items()),
   reply_markup=MENU
  )
  return
 if state=='delete_menu':
  if text=='🗑 حذف موردی': ctx.user_data['state']='delete_one'; await reply(update,'نام دامنه‌ای را که می‌خواهی حذف کنی بفرست:',reply_markup=MENU)
  elif text=='🔥 حذف همه': ctx.user_data['state']='delete_all'; await reply(update,'برای تایید حذف همه دامنه‌ها دقیقا بنویس «حذف همه». برای لغو /cancel را بفرست.')
  else: await reply(update,'یکی از گزینه‌های حذف را انتخاب کن.',reply_markup=DELETE_MENU)
  return
 if state=='delete_one':
  try: d=norm_domain(text)
  except ValueError as e: await reply(update,str(e)+' دوباره نام دامنه را بفرست:'); return
  with db() as c: cur=c.execute('DELETE FROM domains WHERE telegram_id=? AND domain=?',(uid,d))
  ctx.user_data.clear(); await reply(update,('🗑 دامنه حذف شد: ' if cur.rowcount else 'این دامنه در فهرستت نبود: ')+d,reply_markup=MENU); return
 if state=='delete_all':
  if text=='حذف همه':
   with db() as c: cur=c.execute('DELETE FROM domains WHERE telegram_id=?',(uid,))
   ctx.user_data.clear(); await reply(update,f'همه دامنه‌ها حذف شدند ({cur.rowcount} دامنه).',reply_markup=MENU)
  else: ctx.user_data.clear(); await reply(update,'حذف لغو شد.',reply_markup=MENU)
  return
 if state=='update_expiry':
  d=ctx.user_data.get('update_domain')
  try: exp=parse_date(text)
  except ValueError as e: await reply(update,str(e)); return
  days=(date.fromisoformat(exp)-date.today()).days
  with db() as c: cur=c.execute('UPDATE domains SET expiration_date=?,days_left=?,updated_at=? WHERE telegram_id=? AND domain=?',(exp,days,now(),uid,d))
  ctx.user_data.clear(); await reply(update,f'✅ تاریخ انقضای {d} به {exp} تغییر کرد ({days} روز باقی‌مانده).',reply_markup=MENU); return
 await reply(update,'از گزینه‌های منو استفاده کن یا /help را بزن.',reply_markup=MENU)
async def update_button(update:Update,ctx:ContextTypes.DEFAULT_TYPE):
 q=update.callback_query; await q.answer(); d=q.data.split(':',1)[1]; uid=q.from_user.id
 with db() as c: row=c.execute('SELECT domain FROM domains WHERE telegram_id=? AND domain=?',(uid,d)).fetchone()
 if not row: await q.message.reply_text('این دامنه دیگر در فهرستت نیست.',reply_markup=MENU); return
 ctx.user_data['state']='update_expiry'; ctx.user_data['update_domain']=d
 await q.message.reply_text(f'تاریخ انقضای جدید برای {d} را وارد کن (YYYY-MM-DD):',reply_markup=MENU)
async def whois_async(d): return await asyncio.to_thread(whois_expiry,d)
async def weekly_check(ctx:ContextTypes.DEFAULT_TYPE):
 log.info('Starting domain expiration check'); today=date.today()
 with db() as c: users=c.execute('SELECT * FROM users').fetchall()
 for u in users:
  uid,owner,email=u['telegram_id'],u['owner'],u['email']; warnings=[]
  for r in domains_for(uid):
   d=r['domain']
   try: stored_days=(date.fromisoformat(r['expiration_date'])-today).days
   except ValueError: log.exception('Invalid expiry date for %s',d); continue
   with db() as c: c.execute('UPDATE domains SET days_left=? WHERE id=?',(stored_days,r['id']))
   if stored_days>=WARNING_DAYS: continue
   whois_date,error=await whois_async(d)
   with db() as c: c.execute('UPDATE domains SET last_whois_at=? WHERE id=?',(now(),r['id']))
   if whois_date:
    try: whois_days=(date.fromisoformat(whois_date)-today).days
    except ValueError: whois_days=-1
    if whois_days>=WARNING_DAYS:
     with db() as c: c.execute('UPDATE domains SET expiration_date=?,days_left=?,updated_at=? WHERE id=?',(whois_date,whois_days,now(),r['id']))
     continue
   warnings.append((d,f'دامنه {d} در {max(stored_days,0)} روز آینده منقضی می‌شود. در صورت مغایرت اطلاعات، آن را به‌روزرسانی کنید.'))
  if warnings:
   msgs=[x[1] for x in warnings]; keyboard=InlineKeyboardMarkup([[InlineKeyboardButton(f'🔄 به‌روزرسانی {d}',callback_data='update:'+d)] for d,_ in warnings])
   try: await ctx.bot.send_message(chat_id=uid,text='⚠️ هشدار انقضای دامنه\n\n'+'\n\n'.join(msgs),reply_markup=keyboard)
   except Exception: log.exception('Telegram alert failed for %s',uid)
   await asyncio.to_thread(email_alert,email,owner,msgs)
async def check_now(update:Update,ctx:ContextTypes.DEFAULT_TYPE):
 if not user_for(update.effective_user.id): await reply(update,'ابتدا /start را بزن و دامنه اضافه کن.',reply_markup=MENU); return
 await reply(update,'بررسی فوری همه کاربران شروع شد؛ این دستور را فقط در ربات آزمایشی استفاده کن.')
 await weekly_check(ctx)
def main():
 if not TOKEN: raise SystemExit('TELEGRAM_BOT_TOKEN در فایل .env تنظیم نشده است.')
 init_db(); app=Application.builder().token(TOKEN).build()
 app.add_handler(CommandHandler('start',start)); app.add_handler(CommandHandler('help',help_cmd)); app.add_handler(CommandHandler('check',check_now)); app.add_handler(CallbackQueryHandler(update_button,pattern=r'^update:')); app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND,text_handler))
 app.job_queue.run_repeating(weekly_check,interval=CHECK_INTERVAL,first=60)
 log.info('Bot started. SQLite database: %s',DB_PATH); app.run_polling(allowed_updates=Update.ALL_TYPES)
if __name__=='__main__': init_db(); main()
