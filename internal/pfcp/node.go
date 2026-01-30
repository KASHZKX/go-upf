package pfcp

import (
	"fmt"
	"net"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/report"
	logger_util "github.com/free5gc/util/logger"
)

const (
	BUFFQ_LEN = 512
)

type PDRInfo struct {
	RelatedURRIDs map[uint32]struct{}
}

type URRInfo struct {
	removed bool
	SEQN    uint32
	report.MeasureMethod
	report.MeasureInformation
	refPdrNum uint16
}

type Sess struct {
	rnode    *RemoteNode
	LocalID  uint64
	RemoteID uint64
	PDRIDs   map[uint16]*PDRInfo    // key: PDR_ID
	FARIDs   map[uint32]struct{}    // key: FAR_ID
	QERIDs   map[uint32]struct{}    // key: QER_ID
	URRIDs   map[uint32]*URRInfo    // key: URR_ID
	BARIDs   map[uint8]struct{}     // key: BAR_ID
	q        map[uint16]chan []byte // key: PDR_ID
	qlen     int
	log      *logrus.Entry
}

var (
	ErrMissingMandatoryIE             = errors.New("mandatory IE missing or incorrect")
	ErrMissingConditionalIE           = errors.New("conditional IE missing or incorrect")
	ErrRuleNotFound                   = errors.New("rule not found")
	ErrRuleCreationModificationFailed = errors.New("rule creation/modification failed")
)

func (s *Sess) Close() []report.USAReport {
	for id := range s.FARIDs {
		i := ie.NewRemoveFAR(ie.NewFARID(id))
		err := s.RemoveFAR(i)
		if err != nil {
			s.log.Errorf("Remove FAR err: %v", err)
		}
	}
	for id := range s.QERIDs {
		i := ie.NewRemoveQER(ie.NewQERID(id))
		err := s.RemoveQER(i)
		if err != nil {
			s.log.Errorf("Remove QER err: %v", err)
		}
	}

	var usars []report.USAReport
	for id := range s.URRIDs {
		i := ie.NewRemoveURR(ie.NewURRID(id))
		rs, err := s.RemoveURR(i)
		if err != nil {
			s.log.Errorf("Remove URR err: %v", err)
			continue
		}
		if rs != nil {
			usars = append(usars, rs...)
		}
	}
	for id := range s.BARIDs {
		i := ie.NewRemoveBAR(ie.NewBARID(id))
		err := s.RemoveBAR(i)
		if err != nil {
			s.log.Errorf("Remove BAR err: %v", err)
		}
	}
	for id := range s.PDRIDs {
		i := ie.NewRemovePDR(ie.NewPDRID(id))
		rs, err := s.RemovePDR(i)
		if err != nil {
			s.log.Errorf("remove PDR err: %v", err)
		}
		if rs != nil {
			usars = append(usars, rs...)
		}
	}
	for _, q := range s.q {
		close(q)
	}
	return usars
}

func (s *Sess) CreatePDR(req *ie.IE) error {
	ies, err := req.CreatePDR()
	if err != nil {
		return ErrRuleCreationModificationFailed
	}

	if err = s.rnode.driver.CreatePDR(s.LocalID, req); err != nil {
		return ErrRuleCreationModificationFailed
	}

	var pdrid uint16
	urrids := make(map[uint32]struct{})
	for _, i := range ies {
		switch i.Type {
		case ie.PDRID:
			v, err1 := i.PDRID()
			if err1 != nil {
				return ErrMissingMandatoryIE
			}
			pdrid = v
		case ie.URRID:
			v, err1 := i.URRID()
			if err1 != nil {
				return ErrMissingConditionalIE
			}
			_, ok := s.URRIDs[v]
			if !ok {
				return ErrRuleCreationModificationFailed
			}
			urrids[v] = struct{}{}
		}
	}

	for urrid := range urrids {
		urrInfo := s.URRIDs[urrid]
		urrInfo.refPdrNum++
	}

	s.PDRIDs[pdrid] = &PDRInfo{
		RelatedURRIDs: urrids,
	}

	return nil
}

func (s *Sess) diassociateURR(urrid uint32) []report.USAReport {
	urrInfo, ok := s.URRIDs[urrid]
	if !ok {
		return nil
	}

	if urrInfo.refPdrNum > 0 {
		urrInfo.refPdrNum--
		if urrInfo.refPdrNum == 0 {
			// indicates usage report being reported for a URR due to dissociated from the last PDR
			usars, err := s.rnode.driver.QueryURR(s.LocalID, urrid)
			if err != nil {
				return nil
			}
			for i := range usars {
				usars[i].USARTrigger.Flags |= report.USAR_TRIG_TERMR
			}
			return usars
		}
	} else {
		s.log.Errorf("diassociateURR: wrong refPdrNum(%d)", urrInfo.refPdrNum)
	}
	return nil
}

func (s *Sess) UpdatePDR(req *ie.IE) ([]report.USAReport, error) {
	ies, err := req.UpdatePDR()
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	if err = s.rnode.driver.UpdatePDR(s.LocalID, req); err != nil {
		return nil, ErrRuleCreationModificationFailed
	}

	var pdrid uint16
	newUrrids := make(map[uint32]struct{})
	for _, i := range ies {
		switch i.Type {
		case ie.PDRID:
			v, err1 := i.PDRID()
			if err1 != nil {
				return nil, ErrMissingMandatoryIE
			}
			pdrid = v
		case ie.URRID:
			v, err1 := i.URRID()
			if err1 != nil {
				return nil, ErrMissingConditionalIE
			}
			newUrrids[v] = struct{}{}
		}
	}

	pdrInfo, ok := s.PDRIDs[pdrid]
	if !ok {
		return nil, ErrRuleNotFound
	}

	var usars []report.USAReport
	for urrid := range pdrInfo.RelatedURRIDs {
		_, ok = newUrrids[urrid]
		if !ok {
			usar := s.diassociateURR(urrid)
			if len(usar) > 0 {
				usars = append(usars, usar...)
			}
		}
	}
	pdrInfo.RelatedURRIDs = newUrrids

	return usars, err
}

func (s *Sess) RemovePDR(req *ie.IE) ([]report.USAReport, error) {
	pdrid, err := req.PDRID()
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	pdrInfo, ok := s.PDRIDs[pdrid]
	if !ok {
		return nil, ErrRuleNotFound
	}

	if err = s.rnode.driver.RemovePDR(s.LocalID, req); err != nil {
		return nil, ErrRuleCreationModificationFailed
	}

	var usars []report.USAReport
	for urrid := range pdrInfo.RelatedURRIDs {
		usar := s.diassociateURR(urrid)
		if len(usar) > 0 {
			usars = append(usars, usar...)
		}
	}
	delete(s.PDRIDs, pdrid)
	return usars, nil
}

func (s *Sess) CreateFAR(req *ie.IE) error {
	id, err := req.FARID()
	if err != nil {
		return ErrMissingMandatoryIE
	}

	if err := s.rnode.driver.CreateFAR(s.LocalID, req); err != nil {
		return ErrRuleCreationModificationFailed
	}

	s.FARIDs[id] = struct{}{}
	return nil
}

func (s *Sess) UpdateFAR(req *ie.IE) error {
	id, err := req.FARID()
	if err != nil {
		return ErrMissingMandatoryIE
	}

	if _, ok := s.FARIDs[id]; !ok {
		return ErrRuleNotFound
	}
	if err := s.rnode.driver.UpdateFAR(s.LocalID, req); err != nil {
		return ErrRuleCreationModificationFailed
	}
	return nil
}

func (s *Sess) RemoveFAR(req *ie.IE) error {
	id, err := req.FARID()
	if err != nil {
		return ErrMissingMandatoryIE
	}

	_, ok := s.FARIDs[id]
	if !ok {
		return ErrRuleNotFound
	}

	err = s.rnode.driver.RemoveFAR(s.LocalID, req)
	if err != nil {
		return ErrRuleCreationModificationFailed
	}

	delete(s.FARIDs, id)
	return nil
}

func (s *Sess) CreateQER(req *ie.IE) error {
	id, err := req.QERID()
	if err != nil {
		return ErrMissingMandatoryIE
	}

	err = s.rnode.driver.CreateQER(s.LocalID, req)
	if err != nil {
		return ErrRuleCreationModificationFailed
	}

	s.QERIDs[id] = struct{}{}
	return nil
}

func (s *Sess) UpdateQER(req *ie.IE) error {
	id, err := req.QERID()
	if err != nil {
		return ErrMissingMandatoryIE
	}

	if _, ok := s.QERIDs[id]; !ok {
		return ErrRuleNotFound
	}
	if err := s.rnode.driver.UpdateQER(s.LocalID, req); err != nil {
		return ErrRuleCreationModificationFailed
	}
	return nil
}

func (s *Sess) RemoveQER(req *ie.IE) error {
	id, err := req.QERID()
	if err != nil {
		return ErrMissingMandatoryIE
	}

	_, ok := s.QERIDs[id]
	if !ok {
		return ErrRuleNotFound
	}

	if err = s.rnode.driver.RemoveQER(s.LocalID, req); err != nil {
		return ErrRuleCreationModificationFailed
	}

	delete(s.QERIDs, id)
	return nil
}

func (s *Sess) CreateURR(req *ie.IE) error {
	id, err := req.URRID()
	if err != nil {
		return ErrMissingMandatoryIE
	}

	err = s.rnode.driver.CreateURR(s.LocalID, req)
	if err != nil {
		return ErrRuleCreationModificationFailed
	}

	mInfo := &ie.IE{}
	for _, x := range req.ChildIEs {
		if x.Type == ie.MeasurementInformation {
			mInfo = x
			break
		}
	}
	s.URRIDs[id] = &URRInfo{
		MeasureMethod: report.MeasureMethod{
			DURAT: req.HasDURAT(),
			VOLUM: req.HasVOLUM(),
			EVENT: req.HasEVENT(),
		},
		MeasureInformation: report.MeasureInformation{
			MBQE: mInfo.HasMBQE(),
			INAM: mInfo.HasINAM(),
			RADI: mInfo.HasRADI(),
			ISTM: mInfo.HasISTM(),
			MNOP: mInfo.HasMNOP(),
		},
	}
	return nil
}

func (s *Sess) UpdateURR(req *ie.IE) ([]report.USAReport, error) {
	id, err := req.URRID()
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	urrInfo, ok := s.URRIDs[id]
	if !ok {
		return nil, ErrRuleNotFound
	}

	usars, err := s.rnode.driver.UpdateURR(s.LocalID, req)
	if err != nil {
		return nil, ErrRuleCreationModificationFailed
	}

	for _, x := range req.ChildIEs {
		switch x.Type {
		case ie.MeasurementMethod:
			urrInfo.DURAT = x.HasDURAT()
			urrInfo.VOLUM = x.HasVOLUM()
			urrInfo.EVENT = x.HasEVENT()
		case ie.MeasurementInformation:
			urrInfo.MBQE = x.HasMBQE()
			urrInfo.INAM = x.HasINAM()
			urrInfo.RADI = x.HasRADI()
			urrInfo.ISTM = x.HasISTM()
			urrInfo.MNOP = x.HasMNOP()
		}
	}

	return usars, nil
}

func (s *Sess) RemoveURR(req *ie.IE) ([]report.USAReport, error) {
	id, err := req.URRID()
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	info, ok := s.URRIDs[id]
	if !ok {
		return nil, ErrRuleNotFound
	}

	usars, err := s.rnode.driver.RemoveURR(s.LocalID, req)
	if err != nil {
		return nil, ErrRuleCreationModificationFailed
	}

	info.removed = true // remove URRInfo later

	// indicates usage report being reported for a URR due to the removal of the URR
	for i := range usars {
		usars[i].USARTrigger.Flags |= report.USAR_TRIG_TERMR
	}
	return usars, nil
}

func (s *Sess) QueryURR(req *ie.IE) ([]report.USAReport, error) {
	id, err := req.URRID()
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	if _, ok := s.URRIDs[id]; !ok {
		return nil, ErrRuleNotFound
	}

	usars, err := s.rnode.driver.QueryURR(s.LocalID, id)
	if err != nil {
		return nil, ErrRuleCreationModificationFailed
	}

	// indicates an immediate report reported on CP function demand
	for i := range usars {
		usars[i].USARTrigger.Flags |= report.USAR_TRIG_IMMER
	}
	return usars, nil
}

func (s *Sess) CreateBAR(req *ie.IE) error {
	id, err := req.BARID()
	if err != nil {
		return ErrMissingMandatoryIE
	}

	err = s.rnode.driver.CreateBAR(s.LocalID, req)
	if err != nil {
		return ErrRuleCreationModificationFailed
	}

	s.BARIDs[id] = struct{}{}
	return nil
}

func (s *Sess) UpdateBAR(req *ie.IE) error {
	id, err := req.BARID()
	if err != nil {
		return ErrMissingMandatoryIE
	}

	_, ok := s.BARIDs[id]
	if !ok {
		return ErrRuleNotFound
	}
	if err = s.rnode.driver.UpdateBAR(s.LocalID, req); err != nil {
		return ErrRuleCreationModificationFailed
	}
	return nil
}

func (s *Sess) RemoveBAR(req *ie.IE) error {
	id, err := req.BARID()
	if err != nil {
		return ErrMissingMandatoryIE
	}

	_, ok := s.BARIDs[id]
	if !ok {
		return ErrRuleNotFound
	}

	if err = s.rnode.driver.RemoveBAR(s.LocalID, req); err != nil {
		return ErrRuleCreationModificationFailed
	}

	delete(s.BARIDs, id)
	return nil
}

func (s *Sess) Push(pdrid uint16, p []byte) {
	pkt := make([]byte, len(p))
	copy(pkt, p)
	q, ok := s.q[pdrid]
	if !ok {
		s.q[pdrid] = make(chan []byte, s.qlen)
		q = s.q[pdrid]
	}

	select {
	case q <- pkt:
		s.log.Debugf("Push bufPkt to q[%d](len:%d)", pdrid, len(q))
	default:
		s.log.Debugf("q[%d](len:%d) is full, drop it", pdrid, len(q))
	}
}

func (s *Sess) Len(pdrid uint16) int {
	q, ok := s.q[pdrid]
	if !ok {
		return 0
	}
	return len(q)
}

func (s *Sess) Pop(pdrid uint16) ([]byte, bool) {
	q, ok := s.q[pdrid]
	if !ok {
		return nil, ok
	}
	select {
	case pkt := <-q:
		s.log.Debugf("Pop bufPkt from q[%d](len:%d)", pdrid, len(q))
		return pkt, true
	default:
		return nil, false
	}
}

func (s *Sess) URRSeq(urrid uint32) uint32 {
	info, ok := s.URRIDs[urrid]
	if !ok {
		return 0
	}
	seq := info.SEQN
	info.SEQN++
	return seq
}

// ============================================================================
// Validate* methods - validation phase (check state, build plans)
// ============================================================================

// ValidateCreatePDR validates CreatePDR and builds plan without modifying state
func (s *Sess) ValidateCreatePDR(req *ie.IE) (*forwarder.PDRPlan, error) {
	plan, err := s.rnode.driver.BuildCreatePDRPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrRuleCreationModificationFailed
	}

	// Validate URR references exist
	for _, urrid := range plan.URRIDs {
		if _, ok := s.URRIDs[urrid]; !ok {
			return nil, ErrRuleCreationModificationFailed
		}
	}

	return plan, nil
}

// ValidateUpdatePDR validates UpdatePDR and builds plan without modifying state
func (s *Sess) ValidateUpdatePDR(req *ie.IE) (*forwarder.PDRPlan, error) {
	plan, err := s.rnode.driver.BuildUpdatePDRPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	// Validate PDR exists
	if _, ok := s.PDRIDs[plan.PDRID]; !ok {
		return nil, ErrRuleNotFound
	}

	return plan, nil
}

// ValidateRemovePDR validates RemovePDR and builds plan without modifying state
func (s *Sess) ValidateRemovePDR(req *ie.IE) (*forwarder.PDRPlan, error) {
	plan, err := s.rnode.driver.BuildRemovePDRPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	// Validate PDR exists
	if _, ok := s.PDRIDs[plan.PDRID]; !ok {
		return nil, ErrRuleNotFound
	}

	return plan, nil
}

// ValidateCreateFAR validates CreateFAR and builds plan without modifying state
func (s *Sess) ValidateCreateFAR(req *ie.IE) (*forwarder.FARPlan, error) {
	plan, err := s.rnode.driver.BuildCreateFARPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	return plan, nil
}

// ValidateUpdateFAR validates UpdateFAR and builds plan without modifying state
func (s *Sess) ValidateUpdateFAR(req *ie.IE) (*forwarder.FARPlan, error) {
	plan, err := s.rnode.driver.BuildUpdateFARPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	// Validate FAR exists
	if _, ok := s.FARIDs[plan.FARID]; !ok {
		return nil, ErrRuleNotFound
	}

	return plan, nil
}

// ValidateRemoveFAR validates RemoveFAR and builds plan without modifying state
func (s *Sess) ValidateRemoveFAR(req *ie.IE) (*forwarder.FARPlan, error) {
	plan, err := s.rnode.driver.BuildRemoveFARPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	// Validate FAR exists
	if _, ok := s.FARIDs[plan.FARID]; !ok {
		return nil, ErrRuleNotFound
	}

	return plan, nil
}

// ValidateCreateQER validates CreateQER and builds plan without modifying state
func (s *Sess) ValidateCreateQER(req *ie.IE) (*forwarder.QERPlan, error) {
	plan, err := s.rnode.driver.BuildCreateQERPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	return plan, nil
}

// ValidateUpdateQER validates UpdateQER and builds plan without modifying state
func (s *Sess) ValidateUpdateQER(req *ie.IE) (*forwarder.QERPlan, error) {
	plan, err := s.rnode.driver.BuildUpdateQERPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	// Validate QER exists
	if _, ok := s.QERIDs[plan.QERID]; !ok {
		return nil, ErrRuleNotFound
	}

	return plan, nil
}

// ValidateRemoveQER validates RemoveQER and builds plan without modifying state
func (s *Sess) ValidateRemoveQER(req *ie.IE) (*forwarder.QERPlan, error) {
	plan, err := s.rnode.driver.BuildRemoveQERPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	// Validate QER exists
	if _, ok := s.QERIDs[plan.QERID]; !ok {
		return nil, ErrRuleNotFound
	}

	return plan, nil
}

// ValidateCreateURR validates CreateURR and builds plan without modifying state
func (s *Sess) ValidateCreateURR(req *ie.IE) (*forwarder.URRPlan, error) {
	plan, err := s.rnode.driver.BuildCreateURRPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	return plan, nil
}

// ValidateUpdateURR validates UpdateURR and builds plan without modifying state
func (s *Sess) ValidateUpdateURR(req *ie.IE) (*forwarder.URRPlan, error) {
	plan, err := s.rnode.driver.BuildUpdateURRPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	// Validate URR exists
	if _, ok := s.URRIDs[plan.URRID]; !ok {
		return nil, ErrRuleNotFound
	}

	return plan, nil
}

// ValidateRemoveURR validates RemoveURR and builds plan without modifying state
func (s *Sess) ValidateRemoveURR(req *ie.IE) (*forwarder.URRPlan, error) {
	plan, err := s.rnode.driver.BuildRemoveURRPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	// Validate URR exists
	if _, ok := s.URRIDs[plan.URRID]; !ok {
		return nil, ErrRuleNotFound
	}

	return plan, nil
}

// ValidateQueryURR validates QueryURR and builds plan without modifying state
func (s *Sess) ValidateQueryURR(req *ie.IE) (*forwarder.URRPlan, error) {
	plan, err := s.rnode.driver.BuildQueryURRPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	// Validate URR exists
	if _, ok := s.URRIDs[plan.QueryURRID]; !ok {
		return nil, ErrRuleNotFound
	}

	return plan, nil
}

// ValidateCreateBAR validates CreateBAR and builds plan without modifying state
func (s *Sess) ValidateCreateBAR(req *ie.IE) (*forwarder.BARPlan, error) {
	plan, err := s.rnode.driver.BuildCreateBARPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	return plan, nil
}

// ValidateUpdateBAR validates UpdateBAR and builds plan without modifying state
func (s *Sess) ValidateUpdateBAR(req *ie.IE) (*forwarder.BARPlan, error) {
	plan, err := s.rnode.driver.BuildUpdateBARPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	// Validate BAR exists
	if _, ok := s.BARIDs[plan.BARID]; !ok {
		return nil, ErrRuleNotFound
	}

	return plan, nil
}

// ValidateRemoveBAR validates RemoveBAR and builds plan without modifying state
func (s *Sess) ValidateRemoveBAR(req *ie.IE) (*forwarder.BARPlan, error) {
	plan, err := s.rnode.driver.BuildRemoveBARPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	// Validate BAR exists
	if _, ok := s.BARIDs[plan.BARID]; !ok {
		return nil, ErrRuleNotFound
	}

	return plan, nil
}

// ============================================================================
// Apply* methods - apply phase (update internal state after execution)
// ============================================================================

// ApplyCreatePDR updates session state after CreatePDR execution
func (s *Sess) ApplyCreatePDR(plan *forwarder.PDRPlan) {
	urrids := make(map[uint32]struct{})
	for _, urrid := range plan.URRIDs {
		urrids[urrid] = struct{}{}
		if urrInfo, ok := s.URRIDs[urrid]; ok {
			urrInfo.refPdrNum++
		}
	}

	s.PDRIDs[plan.PDRID] = &PDRInfo{
		RelatedURRIDs: urrids,
	}
}

// ApplyUpdatePDR updates session state after UpdatePDR execution
// Returns USAReports from disassociated URRs
func (s *Sess) ApplyUpdatePDR(plan *forwarder.PDRPlan) []report.USAReport {
	pdrInfo, ok := s.PDRIDs[plan.PDRID]
	if !ok {
		return nil
	}

	newUrrids := make(map[uint32]struct{})
	for _, urrid := range plan.URRIDs {
		newUrrids[urrid] = struct{}{}
	}

	var usars []report.USAReport
	for urrid := range pdrInfo.RelatedURRIDs {
		if _, ok := newUrrids[urrid]; !ok {
			usar := s.diassociateURR(urrid)
			if len(usar) > 0 {
				usars = append(usars, usar...)
			}
		}
	}
	pdrInfo.RelatedURRIDs = newUrrids

	return usars
}

// ApplyRemovePDR updates session state after RemovePDR execution
// Returns USAReports from disassociated URRs
func (s *Sess) ApplyRemovePDR(plan *forwarder.PDRPlan) []report.USAReport {
	pdrInfo, ok := s.PDRIDs[plan.PDRID]
	if !ok {
		return nil
	}

	var usars []report.USAReport
	for urrid := range pdrInfo.RelatedURRIDs {
		usar := s.diassociateURR(urrid)
		if len(usar) > 0 {
			usars = append(usars, usar...)
		}
	}
	delete(s.PDRIDs, plan.PDRID)

	return usars
}

// ApplyCreateFAR updates session state after CreateFAR execution
func (s *Sess) ApplyCreateFAR(plan *forwarder.FARPlan) {
	s.FARIDs[plan.FARID] = struct{}{}
}

// ApplyUpdateFAR updates session state after UpdateFAR execution (no state change)
func (s *Sess) ApplyUpdateFAR(plan *forwarder.FARPlan) {
	// No internal state to update for FAR update
}

// ApplyRemoveFAR updates session state after RemoveFAR execution
func (s *Sess) ApplyRemoveFAR(plan *forwarder.FARPlan) {
	delete(s.FARIDs, plan.FARID)
}

// ApplyCreateQER updates session state after CreateQER execution
func (s *Sess) ApplyCreateQER(plan *forwarder.QERPlan) {
	s.QERIDs[plan.QERID] = struct{}{}
}

// ApplyUpdateQER updates session state after UpdateQER execution (no state change)
func (s *Sess) ApplyUpdateQER(plan *forwarder.QERPlan) {
	// No internal state to update for QER update
}

// ApplyRemoveQER updates session state after RemoveQER execution
func (s *Sess) ApplyRemoveQER(plan *forwarder.QERPlan) {
	delete(s.QERIDs, plan.QERID)
}

// ApplyCreateURR updates session state after CreateURR execution
func (s *Sess) ApplyCreateURR(plan *forwarder.URRPlan) {
	mInfo := &ie.IE{}
	if plan.MeasureInfoIE != nil {
		mInfo = plan.MeasureInfoIE
	}

	s.URRIDs[plan.URRID] = &URRInfo{
		MeasureMethod: report.MeasureMethod{
			DURAT: plan.OriginalIE.HasDURAT(),
			VOLUM: plan.OriginalIE.HasVOLUM(),
			EVENT: plan.OriginalIE.HasEVENT(),
		},
		MeasureInformation: report.MeasureInformation{
			MBQE: mInfo.HasMBQE(),
			INAM: mInfo.HasINAM(),
			RADI: mInfo.HasRADI(),
			ISTM: mInfo.HasISTM(),
			MNOP: mInfo.HasMNOP(),
		},
	}
}

// ApplyUpdateURR updates session state after UpdateURR execution
func (s *Sess) ApplyUpdateURR(plan *forwarder.URRPlan) {
	urrInfo, ok := s.URRIDs[plan.URRID]
	if !ok {
		return
	}

	// Update MeasureMethod if present in the plan
	if plan.MeasureMethod != 0 {
		urrInfo.DURAT = (plan.MeasureMethod & 0x01) != 0
		urrInfo.VOLUM = (plan.MeasureMethod & 0x02) != 0
		urrInfo.EVENT = (plan.MeasureMethod & 0x04) != 0
	}

	// Update MeasureInformation if present
	if plan.MeasureInfoIE != nil {
		urrInfo.MBQE = plan.MeasureInfoIE.HasMBQE()
		urrInfo.INAM = plan.MeasureInfoIE.HasINAM()
		urrInfo.RADI = plan.MeasureInfoIE.HasRADI()
		urrInfo.ISTM = plan.MeasureInfoIE.HasISTM()
		urrInfo.MNOP = plan.MeasureInfoIE.HasMNOP()
	}
}

// ApplyRemoveURR updates session state after RemoveURR execution
func (s *Sess) ApplyRemoveURR(plan *forwarder.URRPlan) {
	if info, ok := s.URRIDs[plan.URRID]; ok {
		info.removed = true
	}
}

// ApplyQueryURR - no state change for query
func (s *Sess) ApplyQueryURR(plan *forwarder.URRPlan) {
	// No internal state to update for URR query
}

// ApplyCreateBAR updates session state after CreateBAR execution
func (s *Sess) ApplyCreateBAR(plan *forwarder.BARPlan) {
	s.BARIDs[plan.BARID] = struct{}{}
}

// ApplyUpdateBAR updates session state after UpdateBAR execution (no state change)
func (s *Sess) ApplyUpdateBAR(plan *forwarder.BARPlan) {
	// No internal state to update for BAR update
}

// ApplyRemoveBAR updates session state after RemoveBAR execution
func (s *Sess) ApplyRemoveBAR(plan *forwarder.BARPlan) {
	delete(s.BARIDs, plan.BARID)
}

// CleanupRemovedURRs removes URRInfo entries marked as removed
func (s *Sess) CleanupRemovedURRs() {
	for id, info := range s.URRIDs {
		if info.removed {
			delete(s.URRIDs, id)
		}
	}
}

type RemoteNode struct {
	ID     string
	addr   net.Addr
	local  *LocalNode
	sess   map[uint64]struct{} // key: Local SEID
	driver forwarder.Driver
	log    *logrus.Entry
}

func NewRemoteNode(
	id string,
	addr net.Addr,
	local *LocalNode,
	driver forwarder.Driver,
	log *logrus.Entry,
) *RemoteNode {
	n := new(RemoteNode)
	n.ID = id
	n.addr = addr
	n.local = local
	n.sess = make(map[uint64]struct{})
	n.driver = driver
	n.log = log
	return n
}

func (n *RemoteNode) Reset() {
	for id := range n.sess {
		n.DeleteSess(id)
	}
	n.sess = make(map[uint64]struct{})
}

func (n *RemoteNode) Sess(lSeid uint64) (*Sess, error) {
	_, ok := n.sess[lSeid]
	if !ok {
		return nil, errors.Errorf("Sess: sess not found (lSeid:%#x)", lSeid)
	}
	return n.local.Sess(lSeid)
}

func (n *RemoteNode) NewSess(rSeid uint64) *Sess {
	s := n.local.NewSess(rSeid, BUFFQ_LEN)
	n.sess[s.LocalID] = struct{}{}
	s.rnode = n
	s.log = n.log.WithFields(
		logrus.Fields{
			logger_util.FieldUserPlaneSEID:    fmt.Sprintf("%#x", s.LocalID),
			logger_util.FieldControlPlaneSEID: fmt.Sprintf("%#x", rSeid),
		})
	s.log.Infoln("New session")
	return s
}

func (n *RemoteNode) DeleteSess(lSeid uint64) []report.USAReport {
	_, ok := n.sess[lSeid]
	if !ok {
		return nil
	}
	delete(n.sess, lSeid)
	usars, err := n.local.DeleteSess(lSeid)
	if err != nil {
		n.log.Warnln(err)
		return nil
	}
	return usars
}

type LocalNode struct {
	sess []*Sess
	free []uint64
}

func (n *LocalNode) Reset() {
	for _, sess := range n.sess {
		if sess != nil {
			sess.Close()
		}
	}
	n.sess = []*Sess{}
	n.free = []uint64{}
}

func (n *LocalNode) Sess(lSeid uint64) (*Sess, error) {
	if lSeid == 0 {
		return nil, errors.New("Sess: invalid lSeid:0")
	}

	// Length as int; compare as uint64 to match lSeid type.
	sessLen := len(n.sess)
	if lSeid > uint64(sessLen) {
		return nil, errors.Errorf("Sess: sess not found (lSeid:%#x)", lSeid)
	}

	// Safe: 1 <= lSeid <= sessLen guarantees the conversion and index are valid.
	idx := int(lSeid) - 1
	sess := n.sess[idx]
	if sess == nil {
		return nil, errors.Errorf("Sess: sess not found (lSeid:%#x)", lSeid)
	}
	return sess, nil
}

func (n *LocalNode) RemoteSess(rSeid uint64, addr net.Addr) (*Sess, error) {
	for _, s := range n.sess {
		if s.RemoteID == rSeid && s.rnode.addr.String() == addr.String() {
			return s, nil
		}
	}
	return nil, errors.Errorf("RemoteSess: invalid rSeid:%#x, addr:%s ", rSeid, addr)
}

func (n *LocalNode) NewSess(rSeid uint64, qlen int) *Sess {
	s := &Sess{
		RemoteID: rSeid,
		PDRIDs:   make(map[uint16]*PDRInfo),
		FARIDs:   make(map[uint32]struct{}),
		QERIDs:   make(map[uint32]struct{}),
		URRIDs:   make(map[uint32]*URRInfo),
		BARIDs:   make(map[uint8]struct{}),
		q:        make(map[uint16]chan []byte),
		qlen:     qlen,
	}
	last := len(n.free) - 1
	if last >= 0 {
		s.LocalID = n.free[last]
		n.free = n.free[:last]
		n.sess[s.LocalID-1] = s
	} else {
		n.sess = append(n.sess, s)
		s.LocalID = uint64(len(n.sess))
	}
	return s
}

func (n *LocalNode) DeleteSess(lSeid uint64) ([]report.USAReport, error) {
	if lSeid == 0 {
		return nil, errors.New("DeleteSess: invalid lSeid:0")
	}

	// Capacity as int; compare as uint64 to match lSeid type.
	sessCap := len(n.sess)
	if lSeid > uint64(sessCap) {
		return nil, errors.Errorf("DeleteSess: sess not found (lSeid:%#x)", lSeid)
	}

	// Safe: 1 <= lSeid <= sessCap ensures valid conversion and index.
	idx := int(lSeid) - 1
	if n.sess[idx] == nil {
		return nil, errors.Errorf("DeleteSess: sess not found (lSeid:%#x)", lSeid)
	}

	n.sess[idx].log.Infoln("sess deleted")
	usars := n.sess[idx].Close()
	n.sess[idx] = nil
	n.free = append(n.free, lSeid)

	return usars, nil
}
