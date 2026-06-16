'use client';

import { useRouter } from 'next/navigation';
import { removeToken } from '@/lib/auth';

export default function LogoutButton() {
  const router = useRouter();

  const handleLogout = () => {
    removeToken();
    router.push('/login');
  };

  return (
    <button
      onClick={handleLogout}
      className="text-xs text-[#8b949e] hover:text-[#c9d1d9] border border-[#30363d] rounded px-3 py-1.5 transition-colors"
    >
      Logout
    </button>
  );
}
