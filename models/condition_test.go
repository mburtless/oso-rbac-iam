// Code generated by SQLBoiler 4.7.1 (https://github.com/volatiletech/sqlboiler). DO NOT EDIT.
// This file is meant to be re-generated in place and/or deleted at any time.

package models

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/volatiletech/randomize"
	"github.com/volatiletech/sqlboiler/v4/boil"
	"github.com/volatiletech/sqlboiler/v4/queries"
	"github.com/volatiletech/strmangle"
)

var (
	// Relationships sometimes use the reflection helper queries.Equal/queries.Assign
	// so force a package dependency in case they don't.
	_ = queries.Equal
)

func testConditions(t *testing.T) {
	t.Parallel()

	query := Conditions()

	if query.Query == nil {
		t.Error("expected a query, got nothing")
	}
}

func testConditionsDelete(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Condition{}
	if err = randomize.Struct(seed, o, conditionDBTypes, true, conditionColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Condition struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if rowsAff, err := o.Delete(ctx, tx); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only have deleted one row, but affected:", rowsAff)
	}

	count, err := Conditions().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testConditionsQueryDeleteAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Condition{}
	if err = randomize.Struct(seed, o, conditionDBTypes, true, conditionColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Condition struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if rowsAff, err := Conditions().DeleteAll(ctx, tx); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only have deleted one row, but affected:", rowsAff)
	}

	count, err := Conditions().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testConditionsSliceDeleteAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Condition{}
	if err = randomize.Struct(seed, o, conditionDBTypes, true, conditionColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Condition struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice := ConditionSlice{o}

	if rowsAff, err := slice.DeleteAll(ctx, tx); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only have deleted one row, but affected:", rowsAff)
	}

	count, err := Conditions().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testConditionsExists(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Condition{}
	if err = randomize.Struct(seed, o, conditionDBTypes, true, conditionColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Condition struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	e, err := ConditionExists(ctx, tx, o.ConditionID)
	if err != nil {
		t.Errorf("Unable to check if Condition exists: %s", err)
	}
	if !e {
		t.Errorf("Expected ConditionExists to return true, but got false.")
	}
}

func testConditionsFind(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Condition{}
	if err = randomize.Struct(seed, o, conditionDBTypes, true, conditionColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Condition struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	conditionFound, err := FindCondition(ctx, tx, o.ConditionID)
	if err != nil {
		t.Error(err)
	}

	if conditionFound == nil {
		t.Error("want a record, got nil")
	}
}

func testConditionsBind(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Condition{}
	if err = randomize.Struct(seed, o, conditionDBTypes, true, conditionColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Condition struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if err = Conditions().Bind(ctx, tx, o); err != nil {
		t.Error(err)
	}
}

func testConditionsOne(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Condition{}
	if err = randomize.Struct(seed, o, conditionDBTypes, true, conditionColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Condition struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if x, err := Conditions().One(ctx, tx); err != nil {
		t.Error(err)
	} else if x == nil {
		t.Error("expected to get a non nil record")
	}
}

func testConditionsAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	conditionOne := &Condition{}
	conditionTwo := &Condition{}
	if err = randomize.Struct(seed, conditionOne, conditionDBTypes, false, conditionColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Condition struct: %s", err)
	}
	if err = randomize.Struct(seed, conditionTwo, conditionDBTypes, false, conditionColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Condition struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = conditionOne.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}
	if err = conditionTwo.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice, err := Conditions().All(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if len(slice) != 2 {
		t.Error("want 2 records, got:", len(slice))
	}
}

func testConditionsCount(t *testing.T) {
	t.Parallel()

	var err error
	seed := randomize.NewSeed()
	conditionOne := &Condition{}
	conditionTwo := &Condition{}
	if err = randomize.Struct(seed, conditionOne, conditionDBTypes, false, conditionColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Condition struct: %s", err)
	}
	if err = randomize.Struct(seed, conditionTwo, conditionDBTypes, false, conditionColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Condition struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = conditionOne.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}
	if err = conditionTwo.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Conditions().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 2 {
		t.Error("want 2 records, got:", count)
	}
}

func conditionBeforeInsertHook(ctx context.Context, e boil.ContextExecutor, o *Condition) error {
	*o = Condition{}
	return nil
}

func conditionAfterInsertHook(ctx context.Context, e boil.ContextExecutor, o *Condition) error {
	*o = Condition{}
	return nil
}

func conditionAfterSelectHook(ctx context.Context, e boil.ContextExecutor, o *Condition) error {
	*o = Condition{}
	return nil
}

func conditionBeforeUpdateHook(ctx context.Context, e boil.ContextExecutor, o *Condition) error {
	*o = Condition{}
	return nil
}

func conditionAfterUpdateHook(ctx context.Context, e boil.ContextExecutor, o *Condition) error {
	*o = Condition{}
	return nil
}

func conditionBeforeDeleteHook(ctx context.Context, e boil.ContextExecutor, o *Condition) error {
	*o = Condition{}
	return nil
}

func conditionAfterDeleteHook(ctx context.Context, e boil.ContextExecutor, o *Condition) error {
	*o = Condition{}
	return nil
}

func conditionBeforeUpsertHook(ctx context.Context, e boil.ContextExecutor, o *Condition) error {
	*o = Condition{}
	return nil
}

func conditionAfterUpsertHook(ctx context.Context, e boil.ContextExecutor, o *Condition) error {
	*o = Condition{}
	return nil
}

func testConditionsHooks(t *testing.T) {
	t.Parallel()

	var err error

	ctx := context.Background()
	empty := &Condition{}
	o := &Condition{}

	seed := randomize.NewSeed()
	if err = randomize.Struct(seed, o, conditionDBTypes, false); err != nil {
		t.Errorf("Unable to randomize Condition object: %s", err)
	}

	AddConditionHook(boil.BeforeInsertHook, conditionBeforeInsertHook)
	if err = o.doBeforeInsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeInsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeInsertHook function to empty object, but got: %#v", o)
	}
	conditionBeforeInsertHooks = []ConditionHook{}

	AddConditionHook(boil.AfterInsertHook, conditionAfterInsertHook)
	if err = o.doAfterInsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterInsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterInsertHook function to empty object, but got: %#v", o)
	}
	conditionAfterInsertHooks = []ConditionHook{}

	AddConditionHook(boil.AfterSelectHook, conditionAfterSelectHook)
	if err = o.doAfterSelectHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterSelectHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterSelectHook function to empty object, but got: %#v", o)
	}
	conditionAfterSelectHooks = []ConditionHook{}

	AddConditionHook(boil.BeforeUpdateHook, conditionBeforeUpdateHook)
	if err = o.doBeforeUpdateHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeUpdateHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeUpdateHook function to empty object, but got: %#v", o)
	}
	conditionBeforeUpdateHooks = []ConditionHook{}

	AddConditionHook(boil.AfterUpdateHook, conditionAfterUpdateHook)
	if err = o.doAfterUpdateHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterUpdateHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterUpdateHook function to empty object, but got: %#v", o)
	}
	conditionAfterUpdateHooks = []ConditionHook{}

	AddConditionHook(boil.BeforeDeleteHook, conditionBeforeDeleteHook)
	if err = o.doBeforeDeleteHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeDeleteHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeDeleteHook function to empty object, but got: %#v", o)
	}
	conditionBeforeDeleteHooks = []ConditionHook{}

	AddConditionHook(boil.AfterDeleteHook, conditionAfterDeleteHook)
	if err = o.doAfterDeleteHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterDeleteHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterDeleteHook function to empty object, but got: %#v", o)
	}
	conditionAfterDeleteHooks = []ConditionHook{}

	AddConditionHook(boil.BeforeUpsertHook, conditionBeforeUpsertHook)
	if err = o.doBeforeUpsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeUpsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeUpsertHook function to empty object, but got: %#v", o)
	}
	conditionBeforeUpsertHooks = []ConditionHook{}

	AddConditionHook(boil.AfterUpsertHook, conditionAfterUpsertHook)
	if err = o.doAfterUpsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterUpsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterUpsertHook function to empty object, but got: %#v", o)
	}
	conditionAfterUpsertHooks = []ConditionHook{}
}

func testConditionsInsert(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Condition{}
	if err = randomize.Struct(seed, o, conditionDBTypes, true, conditionColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Condition struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Conditions().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}
}

func testConditionsInsertWhitelist(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Condition{}
	if err = randomize.Struct(seed, o, conditionDBTypes, true); err != nil {
		t.Errorf("Unable to randomize Condition struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Whitelist(conditionColumnsWithoutDefault...)); err != nil {
		t.Error(err)
	}

	count, err := Conditions().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}
}

func testConditionToManyPolicies(t *testing.T) {
	var err error
	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()

	var a Condition
	var b, c Policy

	seed := randomize.NewSeed()
	if err = randomize.Struct(seed, &a, conditionDBTypes, true, conditionColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Condition struct: %s", err)
	}

	if err := a.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}

	if err = randomize.Struct(seed, &b, policyDBTypes, false, policyColumnsWithDefault...); err != nil {
		t.Fatal(err)
	}
	if err = randomize.Struct(seed, &c, policyDBTypes, false, policyColumnsWithDefault...); err != nil {
		t.Fatal(err)
	}

	if err = b.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}
	if err = c.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}

	_, err = tx.Exec("insert into \"condition_policies\" (\"condition_id\", \"policy_id\") values ($1, $2)", a.ConditionID, b.PolicyID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec("insert into \"condition_policies\" (\"condition_id\", \"policy_id\") values ($1, $2)", a.ConditionID, c.PolicyID)
	if err != nil {
		t.Fatal(err)
	}

	check, err := a.Policies().All(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}

	bFound, cFound := false, false
	for _, v := range check {
		if v.PolicyID == b.PolicyID {
			bFound = true
		}
		if v.PolicyID == c.PolicyID {
			cFound = true
		}
	}

	if !bFound {
		t.Error("expected to find b")
	}
	if !cFound {
		t.Error("expected to find c")
	}

	slice := ConditionSlice{&a}
	if err = a.L.LoadPolicies(ctx, tx, false, (*[]*Condition)(&slice), nil); err != nil {
		t.Fatal(err)
	}
	if got := len(a.R.Policies); got != 2 {
		t.Error("number of eager loaded records wrong, got:", got)
	}

	a.R.Policies = nil
	if err = a.L.LoadPolicies(ctx, tx, true, &a, nil); err != nil {
		t.Fatal(err)
	}
	if got := len(a.R.Policies); got != 2 {
		t.Error("number of eager loaded records wrong, got:", got)
	}

	if t.Failed() {
		t.Logf("%#v", check)
	}
}

func testConditionToManyAddOpPolicies(t *testing.T) {
	var err error

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()

	var a Condition
	var b, c, d, e Policy

	seed := randomize.NewSeed()
	if err = randomize.Struct(seed, &a, conditionDBTypes, false, strmangle.SetComplement(conditionPrimaryKeyColumns, conditionColumnsWithoutDefault)...); err != nil {
		t.Fatal(err)
	}
	foreigners := []*Policy{&b, &c, &d, &e}
	for _, x := range foreigners {
		if err = randomize.Struct(seed, x, policyDBTypes, false, strmangle.SetComplement(policyPrimaryKeyColumns, policyColumnsWithoutDefault)...); err != nil {
			t.Fatal(err)
		}
	}

	if err := a.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}
	if err = b.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}
	if err = c.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}

	foreignersSplitByInsertion := [][]*Policy{
		{&b, &c},
		{&d, &e},
	}

	for i, x := range foreignersSplitByInsertion {
		err = a.AddPolicies(ctx, tx, i != 0, x...)
		if err != nil {
			t.Fatal(err)
		}

		first := x[0]
		second := x[1]

		if first.R.Conditions[0] != &a {
			t.Error("relationship was not added properly to the slice")
		}
		if second.R.Conditions[0] != &a {
			t.Error("relationship was not added properly to the slice")
		}

		if a.R.Policies[i*2] != first {
			t.Error("relationship struct slice not set to correct value")
		}
		if a.R.Policies[i*2+1] != second {
			t.Error("relationship struct slice not set to correct value")
		}

		count, err := a.Policies().Count(ctx, tx)
		if err != nil {
			t.Fatal(err)
		}
		if want := int64((i + 1) * 2); count != want {
			t.Error("want", want, "got", count)
		}
	}
}

func testConditionToManySetOpPolicies(t *testing.T) {
	var err error

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()

	var a Condition
	var b, c, d, e Policy

	seed := randomize.NewSeed()
	if err = randomize.Struct(seed, &a, conditionDBTypes, false, strmangle.SetComplement(conditionPrimaryKeyColumns, conditionColumnsWithoutDefault)...); err != nil {
		t.Fatal(err)
	}
	foreigners := []*Policy{&b, &c, &d, &e}
	for _, x := range foreigners {
		if err = randomize.Struct(seed, x, policyDBTypes, false, strmangle.SetComplement(policyPrimaryKeyColumns, policyColumnsWithoutDefault)...); err != nil {
			t.Fatal(err)
		}
	}

	if err = a.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}
	if err = b.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}
	if err = c.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}

	err = a.SetPolicies(ctx, tx, false, &b, &c)
	if err != nil {
		t.Fatal(err)
	}

	count, err := a.Policies().Count(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Error("count was wrong:", count)
	}

	err = a.SetPolicies(ctx, tx, true, &d, &e)
	if err != nil {
		t.Fatal(err)
	}

	count, err = a.Policies().Count(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Error("count was wrong:", count)
	}

	// The following checks cannot be implemented since we have no handle
	// to these when we call Set(). Leaving them here as wishful thinking
	// and to let people know there's dragons.
	//
	// if len(b.R.Conditions) != 0 {
	// 	t.Error("relationship was not removed properly from the slice")
	// }
	// if len(c.R.Conditions) != 0 {
	// 	t.Error("relationship was not removed properly from the slice")
	// }
	if d.R.Conditions[0] != &a {
		t.Error("relationship was not added properly to the slice")
	}
	if e.R.Conditions[0] != &a {
		t.Error("relationship was not added properly to the slice")
	}

	if a.R.Policies[0] != &d {
		t.Error("relationship struct slice not set to correct value")
	}
	if a.R.Policies[1] != &e {
		t.Error("relationship struct slice not set to correct value")
	}
}

func testConditionToManyRemoveOpPolicies(t *testing.T) {
	var err error

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()

	var a Condition
	var b, c, d, e Policy

	seed := randomize.NewSeed()
	if err = randomize.Struct(seed, &a, conditionDBTypes, false, strmangle.SetComplement(conditionPrimaryKeyColumns, conditionColumnsWithoutDefault)...); err != nil {
		t.Fatal(err)
	}
	foreigners := []*Policy{&b, &c, &d, &e}
	for _, x := range foreigners {
		if err = randomize.Struct(seed, x, policyDBTypes, false, strmangle.SetComplement(policyPrimaryKeyColumns, policyColumnsWithoutDefault)...); err != nil {
			t.Fatal(err)
		}
	}

	if err := a.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}

	err = a.AddPolicies(ctx, tx, true, foreigners...)
	if err != nil {
		t.Fatal(err)
	}

	count, err := a.Policies().Count(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Error("count was wrong:", count)
	}

	err = a.RemovePolicies(ctx, tx, foreigners[:2]...)
	if err != nil {
		t.Fatal(err)
	}

	count, err = a.Policies().Count(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Error("count was wrong:", count)
	}

	if len(b.R.Conditions) != 0 {
		t.Error("relationship was not removed properly from the slice")
	}
	if len(c.R.Conditions) != 0 {
		t.Error("relationship was not removed properly from the slice")
	}
	if d.R.Conditions[0] != &a {
		t.Error("relationship was not added properly to the foreign struct")
	}
	if e.R.Conditions[0] != &a {
		t.Error("relationship was not added properly to the foreign struct")
	}

	if len(a.R.Policies) != 2 {
		t.Error("should have preserved two relationships")
	}

	// Removal doesn't do a stable deletion for performance so we have to flip the order
	if a.R.Policies[1] != &d {
		t.Error("relationship to d should have been preserved")
	}
	if a.R.Policies[0] != &e {
		t.Error("relationship to e should have been preserved")
	}
}

func testConditionsReload(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Condition{}
	if err = randomize.Struct(seed, o, conditionDBTypes, true, conditionColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Condition struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if err = o.Reload(ctx, tx); err != nil {
		t.Error(err)
	}
}

func testConditionsReloadAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Condition{}
	if err = randomize.Struct(seed, o, conditionDBTypes, true, conditionColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Condition struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice := ConditionSlice{o}

	if err = slice.ReloadAll(ctx, tx); err != nil {
		t.Error(err)
	}
}

func testConditionsSelect(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Condition{}
	if err = randomize.Struct(seed, o, conditionDBTypes, true, conditionColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Condition struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice, err := Conditions().All(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if len(slice) != 1 {
		t.Error("want one record, got:", len(slice))
	}
}

var (
	conditionDBTypes = map[string]string{`ConditionID`: `integer`, `Type`: `text`, `Value`: `text`}
	_                = bytes.MinRead
)

func testConditionsUpdate(t *testing.T) {
	t.Parallel()

	if 0 == len(conditionPrimaryKeyColumns) {
		t.Skip("Skipping table with no primary key columns")
	}
	if len(conditionAllColumns) == len(conditionPrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}

	seed := randomize.NewSeed()
	var err error
	o := &Condition{}
	if err = randomize.Struct(seed, o, conditionDBTypes, true, conditionColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Condition struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Conditions().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}

	if err = randomize.Struct(seed, o, conditionDBTypes, true, conditionPrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize Condition struct: %s", err)
	}

	if rowsAff, err := o.Update(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only affect one row but affected", rowsAff)
	}
}

func testConditionsSliceUpdateAll(t *testing.T) {
	t.Parallel()

	if len(conditionAllColumns) == len(conditionPrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}

	seed := randomize.NewSeed()
	var err error
	o := &Condition{}
	if err = randomize.Struct(seed, o, conditionDBTypes, true, conditionColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Condition struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Conditions().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}

	if err = randomize.Struct(seed, o, conditionDBTypes, true, conditionPrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize Condition struct: %s", err)
	}

	// Remove Primary keys and unique columns from what we plan to update
	var fields []string
	if strmangle.StringSliceMatch(conditionAllColumns, conditionPrimaryKeyColumns) {
		fields = conditionAllColumns
	} else {
		fields = strmangle.SetComplement(
			conditionAllColumns,
			conditionPrimaryKeyColumns,
		)
	}

	value := reflect.Indirect(reflect.ValueOf(o))
	typ := reflect.TypeOf(o).Elem()
	n := typ.NumField()

	updateMap := M{}
	for _, col := range fields {
		for i := 0; i < n; i++ {
			f := typ.Field(i)
			if f.Tag.Get("boil") == col {
				updateMap[col] = value.Field(i).Interface()
			}
		}
	}

	slice := ConditionSlice{o}
	if rowsAff, err := slice.UpdateAll(ctx, tx, updateMap); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("wanted one record updated but got", rowsAff)
	}
}

func testConditionsUpsert(t *testing.T) {
	t.Parallel()

	if len(conditionAllColumns) == len(conditionPrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}

	seed := randomize.NewSeed()
	var err error
	// Attempt the INSERT side of an UPSERT
	o := Condition{}
	if err = randomize.Struct(seed, &o, conditionDBTypes, true); err != nil {
		t.Errorf("Unable to randomize Condition struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Upsert(ctx, tx, false, nil, boil.Infer(), boil.Infer()); err != nil {
		t.Errorf("Unable to upsert Condition: %s", err)
	}

	count, err := Conditions().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}
	if count != 1 {
		t.Error("want one record, got:", count)
	}

	// Attempt the UPDATE side of an UPSERT
	if err = randomize.Struct(seed, &o, conditionDBTypes, false, conditionPrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize Condition struct: %s", err)
	}

	if err = o.Upsert(ctx, tx, true, nil, boil.Infer(), boil.Infer()); err != nil {
		t.Errorf("Unable to upsert Condition: %s", err)
	}

	count, err = Conditions().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}
	if count != 1 {
		t.Error("want one record, got:", count)
	}
}
