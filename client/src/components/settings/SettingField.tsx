import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { RotateCcw } from 'lucide-react';
import type { SettingValue, SettingsScope } from '@obliwan/shared';
import type { SettingsKey, SettingDefinition } from '@obliwan/shared';
import { InheritanceBadge } from './InheritanceBadge';
import { SETTINGS_KEYS } from '@obliwan/shared';
import { snmpApi, type SnmpCredential } from '@/api/snmp.api';

interface SettingFieldProps {
  definition: SettingDefinition;
  inheritedValue: SettingValue;
  overrideValue: number | undefined;
  scope: SettingsScope;
  onSave: (key: SettingsKey, value: number) => Promise<void>;
  onReset: (key: SettingsKey) => Promise<void>;
}

export function SettingField({
  definition,
  inheritedValue,
  overrideValue,
  scope,
  onSave,
  onReset,
}: SettingFieldProps) {
  const hasOverride = overrideValue !== undefined;
  const [isOverriding, setIsOverriding] = useState(hasOverride);
  const [localValue, setLocalValue] = useState<number>(overrideValue ?? inheritedValue.value);
  const [saving, setSaving] = useState(false);
  const { t } = useTranslation();

  // The only key whose numeric value names a ROW rather than a quantity.
  const isCredentialPicker = definition.key === SETTINGS_KEYS.SNMP_AUTO_TARGET_CREDENTIAL;
  const [credentials, setCredentials] = useState<SnmpCredential[]>([]);
  useEffect(() => {
    if (!isCredentialPicker) return;
    void snmpApi.listCredentials().then(setCredentials).catch(() => setCredentials([]));
  }, [isCredentialPicker]);

  /** Used by the picker: a select has no blur-to-commit, it commits on change. */
  const save = async (value: number) => {
    setSaving(true);
    try {
      await onSave(definition.key, value);
    } finally {
      setSaving(false);
    }
  };

  const handleToggleOverride = async () => {
    if (isOverriding) {
      // Reset to inherited
      setSaving(true);
      try {
        await onReset(definition.key);
        setIsOverriding(false);
        setLocalValue(inheritedValue.value);
      } finally {
        setSaving(false);
      }
    } else {
      // Start overriding
      setIsOverriding(true);
      setLocalValue(inheritedValue.value);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await onSave(definition.key, localValue);
    } finally {
      setSaving(false);
    }
  };

  const handleBlur = () => {
    if (isOverriding && localValue !== overrideValue) {
      handleSave();
    }
  };

  return (
    <div className="flex items-center gap-4 py-3 border-b border-border last:border-b-0">
      {/* Label and description */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-text-primary">{definition.label}</span>
          {scope !== 'global' && (
            isOverriding ? (
              <span className="inline-flex items-center rounded-full bg-amber-500/10 px-2 py-0.5 text-[10px] font-medium text-amber-500">
                Override
              </span>
            ) : (
              <InheritanceBadge setting={inheritedValue} />
            )
          )}
        </div>
        <p className="text-xs text-text-muted mt-0.5">{definition.description}</p>
      </div>

      {/* Value input */}
      <div className="flex items-center gap-2">
        {/* ── One setting is an ID, not a quantity ──────────────────────────
            `snmp_auto_target_credential` holds an `snmp_credentials.id`. The
            settings table stores numbers only, which is the right storage and
            the wrong control: asking an operator to type the numeric id of a
            credential means asking them to go and read it off another screen
            first, and to get it right. The value on the wire is unchanged — a
            number — but it is CHOSEN by name. */}
        {isCredentialPicker ? (
          <select
            value={isOverriding ? localValue : inheritedValue.value}
            onChange={(e) => {
              const next = parseInt(e.target.value, 10) || 0;
              setLocalValue(next);
              void save(next);
            }}
            disabled={scope !== 'global' && !isOverriding}
            className={`w-56 rounded-md border px-2 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-accent ${
              scope !== 'global' && !isOverriding
                ? 'border-border bg-bg-tertiary text-text-muted cursor-not-allowed'
                : 'border-border bg-bg-tertiary text-text-primary'
            }`}
          >
            {/* 0 is not "unset", it is a decision: do not poll automatically. */}
            <option value={0}>{t('snmpCred.noneOption')}</option>
            {credentials.map((c) => (
              <option key={c.id} value={c.id}>{c.name} ({c.version})</option>
            ))}
          </select>
        ) : (
          <input
            type="number"
            value={isOverriding ? localValue : inheritedValue.value}
            onChange={(e) => setLocalValue(parseInt(e.target.value, 10) || 0)}
            onBlur={handleBlur}
            onKeyDown={(e) => {
              if (e.key === 'Enter') handleBlur();
            }}
            disabled={scope !== 'global' && !isOverriding}
            min={definition.min}
            max={definition.max}
            className={`w-24 rounded-md border px-2 py-1 text-sm text-right focus:outline-none focus:ring-2 focus:ring-accent ${
              scope !== 'global' && !isOverriding
                ? 'border-border bg-bg-tertiary text-text-muted cursor-not-allowed'
                : 'border-border bg-bg-tertiary text-text-primary'
            }`}
          />
        )}
        {/* "credential id" is not a unit; the picker already says what it is. */}
        {!isCredentialPicker && (
          <span className="text-xs text-text-muted w-12">{definition.unit}</span>
        )}
      </div>

      {/* Override toggle / reset button (not shown for global scope) */}
      {scope !== 'global' && (
        <button
          onClick={handleToggleOverride}
          disabled={saving}
          className={`shrink-0 rounded-md px-2 py-1 text-xs font-medium transition-colors ${
            isOverriding
              ? 'text-amber-500 hover:bg-amber-500/10'
              : 'text-text-muted hover:bg-bg-hover hover:text-text-primary'
          }`}
          title={isOverriding ? 'Reset to inherited' : 'Override locally'}
        >
          {isOverriding ? (
            <span className="flex items-center gap-1">
              <RotateCcw size={12} />
              Reset
            </span>
          ) : (
            'Override'
          )}
        </button>
      )}
    </div>
  );
}
