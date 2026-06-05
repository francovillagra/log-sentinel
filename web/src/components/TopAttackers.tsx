'use client';

interface Attacker {
  ip: string;
  count: number;
}

interface Props {
  attackers: Attacker[];
}

export default function TopAttackers({ attackers }: Props) {
  const max = attackers[0]?.count ?? 1;

  return (
    <div className="rounded-md border border-[#30363d] bg-[#161b22] p-4">
      <span className="text-xs uppercase tracking-widest text-[#8b949e] block mb-3">
        Top Attackers
      </span>
      {attackers.length === 0 ? (
        <p className="text-xs text-[#484f58]">No data yet.</p>
      ) : (
        <div className="flex flex-col gap-2">
          {attackers.map(({ ip, count }) => (
            <div key={ip} className="flex items-center gap-3">
              <span className="font-mono text-xs text-[#58a6ff] w-32 shrink-0">{ip}</span>
              <div className="flex-1 bg-[#21262d] rounded-full h-1.5 overflow-hidden">
                <div
                  className="h-full rounded-full bg-[#58a6ff]"
                  style={{ width: `${(count / max) * 100}%` }}
                />
              </div>
              <span className="font-mono text-xs text-[#8b949e] w-8 text-right shrink-0">
                {count}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
