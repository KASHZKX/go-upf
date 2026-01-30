package forwarder

import (
	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-upf/internal/report"
)

type Empty struct{}

func (Empty) Close() {
}

func (Empty) CreatePDR(uint64, *ie.IE) error {
	return nil
}

func (Empty) UpdatePDR(uint64, *ie.IE) error {
	return nil
}

func (Empty) RemovePDR(uint64, *ie.IE) error {
	return nil
}

func (Empty) CreateFAR(uint64, *ie.IE) error {
	return nil
}

func (Empty) UpdateFAR(uint64, *ie.IE) error {
	return nil
}

func (Empty) RemoveFAR(uint64, *ie.IE) error {
	return nil
}

func (Empty) CreateQER(uint64, *ie.IE) error {
	return nil
}

func (Empty) UpdateQER(uint64, *ie.IE) error {
	return nil
}

func (Empty) RemoveQER(uint64, *ie.IE) error {
	return nil
}

func (Empty) CreateURR(uint64, *ie.IE) error {
	return nil
}

func (Empty) UpdateURR(uint64, *ie.IE) ([]report.USAReport, error) {
	return nil, nil
}

func (Empty) RemoveURR(uint64, *ie.IE) ([]report.USAReport, error) {
	return nil, nil
}

func (Empty) CreateBAR(uint64, *ie.IE) error {
	return nil
}

func (Empty) UpdateBAR(uint64, *ie.IE) error {
	return nil
}

func (Empty) RemoveBAR(uint64, *ie.IE) error {
	return nil
}

func (Empty) QueryURR(uint64, uint32) ([]report.USAReport, error) {
	return nil, nil
}

func (Empty) HandleReport(report.Handler) {
}

// Plan-based methods for two-phase commit

func (Empty) BuildCreatePDRPlan(lSeid uint64, req *ie.IE) (*PDRPlan, error) {
	return &PDRPlan{}, nil
}

func (Empty) BuildUpdatePDRPlan(lSeid uint64, req *ie.IE) (*PDRPlan, error) {
	return &PDRPlan{}, nil
}

func (Empty) BuildRemovePDRPlan(lSeid uint64, req *ie.IE) (*PDRPlan, error) {
	return &PDRPlan{}, nil
}

func (Empty) BuildCreateFARPlan(lSeid uint64, req *ie.IE) (*FARPlan, error) {
	return &FARPlan{}, nil
}

func (Empty) BuildUpdateFARPlan(lSeid uint64, req *ie.IE) (*FARPlan, error) {
	return &FARPlan{}, nil
}

func (Empty) BuildRemoveFARPlan(lSeid uint64, req *ie.IE) (*FARPlan, error) {
	return &FARPlan{}, nil
}

func (Empty) BuildCreateQERPlan(lSeid uint64, req *ie.IE) (*QERPlan, error) {
	return &QERPlan{}, nil
}

func (Empty) BuildUpdateQERPlan(lSeid uint64, req *ie.IE) (*QERPlan, error) {
	return &QERPlan{}, nil
}

func (Empty) BuildRemoveQERPlan(lSeid uint64, req *ie.IE) (*QERPlan, error) {
	return &QERPlan{}, nil
}

func (Empty) BuildCreateURRPlan(lSeid uint64, req *ie.IE) (*URRPlan, error) {
	return &URRPlan{}, nil
}

func (Empty) BuildUpdateURRPlan(lSeid uint64, req *ie.IE) (*URRPlan, error) {
	return &URRPlan{}, nil
}

func (Empty) BuildRemoveURRPlan(lSeid uint64, req *ie.IE) (*URRPlan, error) {
	return &URRPlan{}, nil
}

func (Empty) BuildQueryURRPlan(lSeid uint64, req *ie.IE) (*URRPlan, error) {
	return &URRPlan{}, nil
}

func (Empty) BuildCreateBARPlan(lSeid uint64, req *ie.IE) (*BARPlan, error) {
	return &BARPlan{}, nil
}

func (Empty) BuildUpdateBARPlan(lSeid uint64, req *ie.IE) (*BARPlan, error) {
	return &BARPlan{}, nil
}

func (Empty) BuildRemoveBARPlan(lSeid uint64, req *ie.IE) (*BARPlan, error) {
	return &BARPlan{}, nil
}

func (Empty) ExecuteModificationPlan(plan *ModificationPlan, dryRun bool) (*ExecutionResult, error) {
	return NewExecutionResult(), nil
}
