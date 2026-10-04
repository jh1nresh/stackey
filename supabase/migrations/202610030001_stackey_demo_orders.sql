-- Stackey sandbox only: synthetic data, no personal or payment credentials.
begin;
create table if not exists public.stackey_demo_orders (
  id text primary key,
  created_at timestamptz not null,
  currency text not null check (currency in ('USD','TWD')),
  amount_minor bigint not null check (amount_minor >= 0),
  payment_status text not null check (payment_status in ('paid','payment_failed'))
);
alter table public.stackey_demo_orders enable row level security;
revoke all on public.stackey_demo_orders from anon, authenticated;
grant select on public.stackey_demo_orders to service_role;
create index if not exists stackey_demo_orders_time_id on public.stackey_demo_orders(created_at,id);
insert into public.stackey_demo_orders(id,created_at,currency,amount_minor,payment_status)
select 'demo-'||day||'-'||kind,
  timestamptz '2026-09-26 00:00:00+00' + day * interval '1 day' + hour * interval '1 hour',
  currency, amount + day * increment, status
from generate_series(0,6) as day
cross join (values
  ('usd',9,'USD',1000,100,'paid'),
  ('twd',10,'TWD',30000,1000,'paid'),
  ('failed',11,'USD',1200,0,'payment_failed')
) as sample(kind,hour,currency,amount,increment,status)
on conflict (id) do nothing;
commit;
select count(*) as synthetic_orders,
  count(*) filter (where payment_status='payment_failed') as failed_orders
from public.stackey_demo_orders;
