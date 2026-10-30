-- Roman's City · Supabase setup
-- Run once in Supabase → SQL Editor → New query → paste everything → Run.
-- Safe to run again: it drops and recreates the functions, triggers and policies.

-- ============ TABLES ============
create table if not exists public.chat_messages (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid(),
  name text not null default 'Player',
  color smallint not null default 0,
  body text not null,
  hidden boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists chat_messages_created_idx on public.chat_messages (created_at desc);
create index if not exists chat_messages_user_idx on public.chat_messages (user_id, created_at desc);

create table if not exists public.reports (
  id bigint generated always as identity primary key,
  reporter uuid not null default auth.uid(),
  reported uuid not null,
  message_id bigint references public.chat_messages(id) on delete set null,
  reason text not null default 'chat',
  created_at timestamptz not null default now(),
  unique (reporter, message_id)
);

-- Owner moderation: add a row here to mute someone (until = null means forever).
create table if not exists public.banned (
  user_id uuid primary key,
  until timestamptz,
  reason text,
  created_at timestamptz not null default now()
);

create table if not exists public.ski_times (
  user_id uuid not null default auth.uid(),
  mode text not null check (mode in ('ski','board')),
  t numeric(6,2) not null check (t >= 15 and t < 600),
  name text not null default 'Player',
  at timestamptz not null default now(),
  primary key (user_id, mode)
);
create index if not exists ski_times_mode_t_idx on public.ski_times (mode, t);

-- ============ HELPERS ============
-- normalizes text so "F.u.c.k", "fvck", "5h1t" style tricks are caught
create or replace function public.rc_spaced(s text) returns text
language sql immutable as $$
  select btrim(regexp_replace(
           translate(lower(coalesce(s,'')), '0@4!1|3$57áéíóúüñ', 'oaaiiiesstaeiouun'),
           '[^a-z]+', ' ', 'g'))
$$;

create or replace function public.rc_bad(s text) returns boolean
language sql immutable as $$
  select replace(public.rc_spaced(s), ' ', '') ~ '(fuck|fvck|fuk|fck|motherf|nigg|faggot|whore|bitch|cunt|pussy|onlyfans|killyourself|pendej|chinga|culero|hitler|shit|mierda|maric|verga|nudes)'
      or exists (select 1 from regexp_split_to_table(public.rc_spaced(s), ' ') w
                 where w ~ '^(fag|fags|sex|sexy|rape|raped|rapist|dick|dicks|cock|cocks|puta|putas|puto|putos|joto|jotos|zorra|perra|cabron|polla|porn|porno|nude|nudes|kys|kkk|nazi|nazis|retard|retarded|slut|sluts|cum|tits|mamada|pinche|wey)$')
$$;

-- links, emails, phone numbers, social handles: blocked to protect players
create or replace function public.rc_contact(s text) returns boolean
language sql immutable as $$
  select s ~* '(https?://|www\.|\.(com|net|org|io|gg|me|ly|co|app|xyz|tv)\y|\ydiscord|\ysnap(chat)?\y|\yinsta(gram)?\y|\ytiktok|whats ?app|telegram|\ykik\y|@[a-z0-9_]{3,})'
      or s ~ '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
      or exists (select 1 from regexp_matches(s, '(\+?[0-9][0-9 ().-]{5,}[0-9])', 'g') as m(x)
                 where length(regexp_replace((m.x)[1], '[^0-9]', '', 'g')) >= 7)
$$;

create or replace function public.rc_is_banned(uid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.banned b where b.user_id = uid and (b.until is null or b.until > now()))
$$;

create or replace function public.rc_clean_name(n text) returns text
language sql immutable as $$
  select case
    when n is null or length(btrim(n)) = 0 then 'Player'
    when public.rc_bad(n) or public.rc_contact(n) then 'Player'
    else left(regexp_replace(btrim(n), '[[:cntrl:]<>]', '', 'g'), 16)
  end
$$;

-- ============ CHAT RULES (run on the server, cannot be skipped) ============
create or replace function public.rc_chat_guard() returns trigger
language plpgsql security definer set search_path = public as $$
declare n_recent int; last_at timestamptz;
begin
  new.user_id := auth.uid();
  if new.user_id is null then raise exception 'not_signed_in'; end if;
  if public.rc_is_banned(new.user_id) then raise exception 'muted'; end if;
  new.body := btrim(regexp_replace(coalesce(new.body,''), '[[:cntrl:]]', ' ', 'g'));
  if length(new.body) < 1 or length(new.body) > 140 then raise exception 'length'; end if;
  if public.rc_bad(new.body) then raise exception 'blocked_word'; end if;
  if public.rc_contact(new.body) then raise exception 'blocked_contact'; end if;
  select max(created_at), count(*) filter (where created_at > now() - interval '30 seconds')
    into last_at, n_recent from public.chat_messages where user_id = new.user_id and created_at > now() - interval '30 seconds';
  if last_at is not null and last_at > now() - interval '1.5 seconds' then raise exception 'slow_down'; end if;
  if n_recent >= 8 then raise exception 'slow_down'; end if;
  if exists (select 1 from public.chat_messages where user_id = new.user_id and body = new.body and created_at > now() - interval '60 seconds') then
    raise exception 'repeat'; end if;
  new.name := public.rc_clean_name(new.name);
  new.color := greatest(0, least(7, coalesce(new.color,0)));
  new.hidden := false;
  new.created_at := now();
  return new;
end $$;
drop trigger if exists rc_chat_guard on public.chat_messages;
create trigger rc_chat_guard before insert on public.chat_messages for each row execute function public.rc_chat_guard();

-- ============ REPORTS: 3 reports hide a message, 5 people reporting someone in 24h mutes them for 24h ============
create or replace function public.rc_report_guard() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  new.reporter := auth.uid();
  if new.reporter is null then raise exception 'not_signed_in'; end if;
  if new.reporter = new.reported then raise exception 'self'; end if;
  if (select count(*) from public.reports where reporter = new.reporter and created_at > now() - interval '1 hour') >= 15 then
    raise exception 'slow_down'; end if;
  new.reason := left(coalesce(new.reason,'chat'), 40);
  new.created_at := now();
  return new;
end $$;
drop trigger if exists rc_report_guard on public.reports;
create trigger rc_report_guard before insert on public.reports for each row execute function public.rc_report_guard();

create or replace function public.rc_report_after() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.message_id is not null and
     (select count(distinct reporter) from public.reports where message_id = new.message_id) >= 3 then
    update public.chat_messages set hidden = true where id = new.message_id;
  end if;
  if (select count(distinct reporter) from public.reports where reported = new.reported and created_at > now() - interval '24 hours') >= 5 then
    insert into public.banned (user_id, until, reason) values (new.reported, now() + interval '24 hours', 'auto: reports')
    on conflict (user_id) do update set until = greatest(coalesce(public.banned.until, 'infinity'::timestamptz), excluded.until)
      where public.banned.until is not null;
  end if;
  return null;
end $$;
drop trigger if exists rc_report_after on public.reports;
create trigger rc_report_after after insert on public.reports for each row execute function public.rc_report_after();

-- ============ HALL OF FAME (only through these two functions) ============
create or replace function public.rc_submit_time(p_mode text, p_t numeric, p_name text) returns boolean
language plpgsql security definer set search_path = public as $$
declare uid uuid := auth.uid(); old_t numeric;
begin
  if uid is null then raise exception 'not_signed_in'; end if;
  if p_mode not in ('ski','board') then raise exception 'mode'; end if;
  if p_t is null or p_t < 15 or p_t >= 600 then raise exception 'time'; end if;
  select t into old_t from public.ski_times where user_id = uid and mode = p_mode;
  if old_t is not null and old_t <= p_t then return false; end if;
  insert into public.ski_times (user_id, mode, t, name, at)
  values (uid, p_mode, round(p_t, 2), public.rc_clean_name(p_name), now())
  on conflict (user_id, mode) do update set t = excluded.t, name = excluded.name, at = excluded.at;
  return true;
end $$;

create or replace function public.rc_delete_my_data() returns void
language sql security definer set search_path = public as $$
  delete from public.ski_times where user_id = auth.uid();
$$;

revoke all on function public.rc_submit_time(text, numeric, text) from public, anon;
revoke all on function public.rc_delete_my_data() from public, anon;
grant execute on function public.rc_submit_time(text, numeric, text) to authenticated;
grant execute on function public.rc_delete_my_data() to authenticated;

drop trigger if exists rc_times_guard on public.ski_times;
drop function if exists public.rc_times_guard();

-- ============ ROW LEVEL SECURITY ============
alter table public.chat_messages enable row level security;
alter table public.reports enable row level security;
alter table public.banned enable row level security;
alter table public.ski_times enable row level security;

drop policy if exists chat_read on public.chat_messages;
drop policy if exists chat_write on public.chat_messages;
create policy chat_read on public.chat_messages for select to anon, authenticated
  using (created_at > now() - interval '24 hours');
create policy chat_write on public.chat_messages for insert to authenticated
  with check (user_id = auth.uid());

drop policy if exists reports_write on public.reports;
create policy reports_write on public.reports for insert to authenticated
  with check (reporter = auth.uid());
-- (no select policy: only you can read reports, from the dashboard)

-- banned: no policies at all → only you (dashboard) can read or change it

drop policy if exists times_read on public.ski_times;
drop policy if exists times_insert on public.ski_times;
drop policy if exists times_update on public.ski_times;
drop policy if exists times_delete on public.ski_times;
create policy times_read on public.ski_times for select to anon, authenticated using (true);
-- no write policies: times are written only by rc_submit_time / rc_delete_my_data

-- only the columns the game needs can be written
revoke all on public.chat_messages, public.reports, public.banned, public.ski_times from anon, authenticated;
grant select on public.chat_messages, public.ski_times to anon, authenticated;
grant insert (name, color, body) on public.chat_messages to authenticated;
grant insert (reported, message_id, reason) on public.reports to authenticated;

revoke all on function public.rc_is_banned(uuid) from public, anon, authenticated;
revoke all on function public.rc_chat_guard() from public, anon, authenticated;
revoke all on function public.rc_report_guard() from public, anon, authenticated;
revoke all on function public.rc_report_after() from public, anon, authenticated;

-- ============ LIVE UPDATES ============
do $$ begin
  begin alter publication supabase_realtime add table public.chat_messages; exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.ski_times; exception when duplicate_object then null; end;
end $$;

-- ============ HOUSEKEEPING: every night delete chat older than 7 days, reports older than 90 days, expired mutes ============
do $outer$ begin
  create extension if not exists pg_cron;
  perform cron.schedule('rc-cleanup', '17 9 * * *', $job$
    delete from public.chat_messages where created_at < now() - interval '7 days';
    delete from public.reports where created_at < now() - interval '90 days';
    delete from public.banned where until is not null and until < now();
  $job$);
exception when others then
  raise notice 'pg_cron is not available (%). Turn it on in Database → Extensions → pg_cron and run this file again.', sqlerrm;
end $outer$;
