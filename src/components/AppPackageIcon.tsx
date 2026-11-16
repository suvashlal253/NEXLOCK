import React from 'react';
import {
  Briefcase,
  Camera,
  CreditCard,
  FileSpreadsheet,
  Gamepad2,
  Globe,
  HelpCircle,
  Lock,
  Mail,
  MessageCircle,
  Music,
  Package,
  PlaySquare,
  Settings,
  Share2,
  ShoppingBag,
  Shield,
  Wrench,
} from 'lucide-react';
import { AppCategoryType } from '../types/nexlock';

interface AppPackageIconProps {
  packageName: string;
  appName: string;
  category: AppCategoryType;
  accentHex: string;
  hasValidIconResource?: boolean;
  size?: 'sm' | 'md' | 'lg';
}

/**
 * Renders an aspect-ratio-preserving Android adaptive icon representation for a package
 * retrieved from AppDiscoveryRepository / AppIconMemoryCache.
 * If hasValidIconResource is false (simulating PackageManager.NameNotFoundException or missing icon),
 * renders a neutral fallback package icon without crashing.
 */
export const AppPackageIcon: React.FC<AppPackageIconProps> = ({
  packageName,
  appName,
  category,
  accentHex,
  hasValidIconResource = true,
  size = 'md',
}) => {
  const pkg = packageName.toLowerCase();

  const dimensions =
    size === 'sm'
      ? 'w-10 h-10 rounded-xl'
      : size === 'lg'
      ? 'w-14 h-14 rounded-2xl'
      : 'w-11 h-11 rounded-2xl';

  const iconSize = size === 'sm' ? 'w-5 h-5' : size === 'lg' ? 'w-7 h-7' : 'w-5 h-5';

  // Fallback icon when PackageManager cannot retrieve an icon Drawable
  if (!hasValidIconResource) {
    return (
      <div
        title={`Fallback icon for ${appName} (${packageName})`}
        className={`${dimensions} bg-slate-200 dark:bg-white/10 text-slate-500 dark:text-[#A6B0C3] flex items-center justify-center shrink-0 aspect-square border border-slate-300/60 dark:border-white/10`}
      >
        <Package className={iconSize} />
      </div>
    );
  }

  let IconComponent = HelpCircle;
  if (pkg.includes('whatsapp') || pkg.includes('securesms') || pkg.includes('telegram') || pkg.includes('messaging')) {
    IconComponent = MessageCircle;
  } else if (pkg.includes('gm') || pkg.includes('mail') || pkg.includes('outlook')) {
    IconComponent = Mail;
  } else if (pkg.includes('revolut') || pkg.includes('coinbase') || pkg.includes('paypal') || pkg.includes('wallet')) {
    IconComponent = CreditCard;
  } else if (pkg.includes('photos') || pkg.includes('camera') || pkg.includes('lrmobile')) {
    IconComponent = Camera;
  } else if (pkg.includes('settings')) {
    IconComponent = Settings;
  } else if (pkg.includes('youtube') || pkg.includes('netflix')) {
    IconComponent = PlaySquare;
  } else if (pkg.includes('spotify') || pkg.includes('music')) {
    IconComponent = Music;
  } else if (pkg.includes('amazon') || pkg.includes('shopify') || pkg.includes('ebay')) {
    IconComponent = ShoppingBag;
  } else if (pkg.includes('docs') || pkg.includes('sheets') || pkg.includes('notion')) {
    IconComponent = FileSpreadsheet;
  } else if (pkg.includes('slack') || pkg.includes('office')) {
    IconComponent = Briefcase;
  } else if (pkg.includes('chrome') || pkg.includes('browser')) {
    IconComponent = Globe;
  } else if (pkg.includes('1password') || pkg.includes('bitwarden')) {
    IconComponent = Lock;
  } else {
    switch (category) {
      case 'Communication':
        IconComponent = MessageCircle;
        break;
      case 'Social Media':
        IconComponent = Share2;
        break;
      case 'Finance':
        IconComponent = CreditCard;
        break;
      case 'Shopping':
        IconComponent = ShoppingBag;
        break;
      case 'Photography':
        IconComponent = Camera;
        break;
      case 'Entertainment':
        IconComponent = PlaySquare;
        break;
      case 'Productivity':
        IconComponent = Briefcase;
        break;
      case 'Games':
        IconComponent = Gamepad2;
        break;
      case 'Tools':
        IconComponent = Wrench;
        break;
      default:
        IconComponent = Shield;
        break;
    }
  }

  return (
    <div
      className={`${dimensions} flex items-center justify-center text-white shrink-0 aspect-square shadow-sm`}
      style={{ backgroundColor: accentHex }}
    >
      <IconComponent className={iconSize} />
    </div>
  );
};
