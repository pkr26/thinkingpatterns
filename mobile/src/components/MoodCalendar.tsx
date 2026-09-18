/**
 * Month calendar with per-day mood dots (2026-09-17).
 *
 * The audit found History was a 50-per-page linear scroll — unusable past
 * a few months. This calendar gives the at-a-glance month: every journaled
 * day carries a dot colored by that day's check-in (green up, red down,
 * neutral gray), missing days stay blank (no guilt). Tapping a journaled
 * day filters the list to it; tapping it again (or a blank day) clears
 * the filter.
 */
import React, { useMemo, useState } from "react";
import { StyleSheet, Text, TouchableOpacity, View } from "react-native";
import { useTheme } from "../theme";
import { CalendarDay, monthGrid, monthLabel, stepMonth } from "../historyFind";

const WEEKDAY_LABELS = ["M", "T", "W", "T", "F", "S", "S"] as const;

export function MoodCalendar({
  dayMoods,
  journaledDays,
  selectedDay,
  onSelectDay,
}: {
  /** ISO date -> mood value in [-1, 1] (the device-local mood log). */
  dayMoods: Record<string, number>;
  /** ISO dates that have entries (any mood). */
  journaledDays: Set<string>;
  selectedDay: string | null;
  onSelectDay: (iso: string | null) => void;
}): React.JSX.Element {
  const t = useTheme();
  const now = new Date();
  const [view, setView] = useState({ year: now.getFullYear(), month: now.getMonth() + 1 });
  const cells = useMemo(() => monthGrid(view.year, view.month), [view.year, view.month]);

  const dotColor = (iso: string): string | null => {
    if (!journaledDays.has(iso)) return null;
    const mood = dayMoods[iso];
    if (typeof mood !== "number" || !Number.isFinite(mood) || mood === 0) return t.colors.muted;
    return mood > 0 ? t.colors.success : t.colors.sparkDown;
  };

  return (
    <View
      style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg }]}
      accessibilityRole="summary"
      accessibilityLabel={`Calendar, ${monthLabel(view.year, view.month)}. Dots mark journaled days.`}
    >
      <View style={styles.header}>
        <TouchableOpacity
          onPress={() => setView(stepMonth(view.year, view.month, -1))}
          accessibilityRole="button"
          accessibilityLabel="Previous month"
          hitSlop={t.touchSlop}
          style={styles.arrow}
        >
          <Text style={{ color: t.colors.accent, fontSize: 16 }}>‹</Text>
        </TouchableOpacity>
        <Text style={{ color: t.colors.text, fontSize: t.type.bodySmall.fontSize, fontWeight: "600" }}>
          {monthLabel(view.year, view.month)}
        </Text>
        <TouchableOpacity
          onPress={() => setView(stepMonth(view.year, view.month, 1))}
          accessibilityRole="button"
          accessibilityLabel="Next month"
          hitSlop={t.touchSlop}
          style={styles.arrow}
        >
          <Text style={{ color: t.colors.accent, fontSize: 16 }}>›</Text>
        </TouchableOpacity>
      </View>
      <View style={styles.grid}>
        {WEEKDAY_LABELS.map((label, i) => (
          <Text key={`${label}-${i}`} style={{ color: t.colors.muted, fontSize: 10, textAlign: "center", width: CELL_WIDTH }}>
            {label}
          </Text>
        ))}
        {cells.map((cell: CalendarDay, i) => {
          if (cell.iso === null) return <View key={`blank-${i}`} style={{ width: CELL_WIDTH, minHeight: t.minTouch }} />;
          const journaled = journaledDays.has(cell.iso);
          const selected = selectedDay === cell.iso;
          const color = dotColor(cell.iso);
          return (
            <TouchableOpacity
              key={cell.iso}
              style={[
                styles.day,
                {
                  backgroundColor: selected ? t.colors.primary : "transparent",
                  borderRadius: t.radius.sm,
                  minHeight: t.minTouch,
                },
              ]}
              // A blank day is still a useful target: it clears a selected
              // filter. Previously it was disabled, trapping a person in a
              // day filter unless they found the selected day again.
              onPress={() => onSelectDay(selected ? null : journaled ? cell.iso! : null)}
              accessibilityRole="button"
              accessibilityLabel={
                journaled
                  ? `${cell.iso}, journaled${selected ? ", selected" : ""}`
                  : `${cell.iso}, no entry`
              }
              accessibilityState={selected ? { selected: true } : undefined}
            >
              <Text
                style={{
                  color: selected ? t.colors.onPrimary : journaled ? t.colors.body : t.colors.muted,
                  fontSize: 11,
                  textAlign: "center",
                }}
              >
                {cell.day}
              </Text>
              {color && !selected && <View style={[styles.dot, { backgroundColor: color }]} />}
            </TouchableOpacity>
          );
        })}
      </View>
    </View>
  );
}

/** Seven 44pt targets fit responsively instead of using a fixed 38pt grid
 * that was too small for touch accessibility and overflowed narrow phones. */
const CELL_WIDTH = "14.2857%";
const styles = StyleSheet.create({
  card: { padding: 12, gap: 8 },
  header: { flexDirection: "row", alignItems: "center", justifyContent: "space-between" },
  arrow: { paddingHorizontal: 12, paddingVertical: 4, minHeight: 44, minWidth: 44, justifyContent: "center", alignItems: "center" },
  grid: { flexDirection: "row", flexWrap: "wrap" },
  day: { width: CELL_WIDTH, alignItems: "center", justifyContent: "center", gap: 1 },
  dot: { width: 4, height: 4, borderRadius: 2 },
});
