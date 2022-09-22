package gojwt

import (
	"strconv"
	"time"
)

type Time struct {
	time.Time
}

func Wrap(time time.Time) *Time {
	return &Time{Time: time}
}

func Now() *Time {
	return Wrap(time.Now())
}

func Unix(seconds int64) *Time {
	return Wrap(time.Unix(seconds, 0))
}

func (t *Time) Add(duration time.Duration) *Time {
	t.Time = t.Time.Add(duration)
	return t
}

func (t *Time) MarshalText() ([]byte, error) {
	if t.Time.IsZero() {
		return []byte("null"), nil
	}
	return []byte(strconv.FormatInt(t.Time.Unix(), 10)), nil
}

func (t *Time) UnmarshalText(data []byte) error {
	res, err := strconv.ParseInt(string(data), 10, 64)
	t.Time = time.Unix(res, 0)
	return err
}

func (t *Time) MarshalJSON() ([]byte, error) {
	return t.MarshalText()
}

func (t *Time) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	return t.UnmarshalText(data)
}
