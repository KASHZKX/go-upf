package pfcp

import (
	"net"

	"github.com/pkg/errors"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/report"
)

func (s *PfcpServer) handleSessionEstablishmentRequest(
	req *message.SessionEstablishmentRequest,
	addr net.Addr,
) {
	s.log.Infoln("handleSessionEstablishmentRequest")

	if req.NodeID == nil {
		s.log.Errorln("not found NodeID")
		s.sendSessEstFailRsp(req, addr, ie.CauseMandatoryIEMissing)
		return
	}
	rnodeid, err := req.NodeID.NodeID()
	if err != nil {
		s.log.Errorln(err)
		s.sendSessEstFailRsp(req, addr, ie.CauseMandatoryIEMissing)
		return
	}
	s.log.Debugf("remote nodeid: %v\n", rnodeid)

	rnode, ok := s.rnodes[rnodeid]
	if !ok {
		s.log.Errorf("not found NodeID %v\n", rnodeid)
		s.sendSessEstFailRsp(req, addr, ie.CauseNoEstablishedPFCPAssociation)
		return
	}

	if req.CPFSEID == nil {
		s.log.Errorln("not found CP F-SEID")
		s.sendSessEstFailRsp(req, addr, ie.CauseMandatoryIEMissing)
		return
	}
	fseid, err := req.CPFSEID.FSEID()
	if err != nil {
		s.log.Errorln(err)
		s.sendSessEstFailRsp(req, addr, ie.CauseMandatoryIEMissing)
		return
	}
	s.log.Debugf("fseid.SEID: %#x\n", fseid.SEID)

	// allocate a session
	sess := rnode.NewSess(fseid.SEID)

	// TODO: rollback transaction
	// Solved by deleting sess if one of operation fails (all or nothing)
	for _, i := range req.CreateFAR {
		if err = sess.CreateFAR(i); err != nil {
			sess.log.Errorf("Est CreateFAR error: %v", err)
			cause := pfcpCauseFromError(err)
			s.sendSessEstFailRsp(req, addr, cause)
			rnode.DeleteSess(sess.LocalID)
			return
		}
	}

	for _, i := range req.CreateQER {
		if err = sess.CreateQER(i); err != nil {
			sess.log.Errorf("Est CreateQER error: %v", err)
			cause := pfcpCauseFromError(err)
			s.sendSessEstFailRsp(req, addr, cause)
			rnode.DeleteSess(sess.LocalID)
			return
		}
	}

	for _, i := range req.CreateURR {
		if err = sess.CreateURR(i); err != nil {
			sess.log.Errorf("Est CreateURR error: %v", err)
			cause := pfcpCauseFromError(err)
			s.sendSessEstFailRsp(req, addr, cause)
			rnode.DeleteSess(sess.LocalID)
			return
		}
	}

	if req.CreateBAR != nil {
		if err = sess.CreateBAR(req.CreateBAR); err != nil {
			sess.log.Errorf("Est CreateBAR error: %v", err)
			cause := pfcpCauseFromError(err)
			s.sendSessEstFailRsp(req, addr, cause)
			rnode.DeleteSess(sess.LocalID)
			return
		}
	}

	CreatedPDRList := make([]*ie.IE, 0)

	for _, i := range req.CreatePDR {
		if err = sess.CreatePDR(i); err != nil {
			sess.log.Errorf("Est CreatePDR error: %v", err)
			cause := pfcpCauseFromError(err)
			s.sendSessEstFailRsp(req, addr, cause)
			rnode.DeleteSess(sess.LocalID)
			return
		}

		ueIPAddress := getUEAddressFromPDR(i)
		pdrId := getPDRIDFromPDR(i)

		if ueIPAddress != nil {
			ueIPv4 := ueIPAddress.IPv4Address.String()
			CreatedPDRList = append(CreatedPDRList, ie.NewCreatedPDR(
				ie.NewPDRID(pdrId),
				ie.NewUEIPAddress(2, ueIPv4, "", 0, 0),
			))
		}
	}

	var v4 net.IP
	addrv4, err := net.ResolveIPAddr("ip4", s.nodeID)
	if err == nil {
		v4 = addrv4.IP.To4()
	}
	// TODO: support v6
	var v6 net.IP

	ies := make([]*ie.IE, 0)
	ies = append(ies, CreatedPDRList...)
	ies = append(ies,
		newIeNodeID(s.nodeID),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewFSEID(sess.LocalID, v4, v6))

	rsp := message.NewSessionEstablishmentResponse(
		0,             // mp
		0,             // fo
		sess.RemoteID, // seid
		req.Header.SequenceNumber,
		0, // pri
		ies...,
	)

	err = s.sendRspTo(rsp, addr)
	if err != nil {
		s.log.Errorln(err)
		return
	}
}

func (s *PfcpServer) handleSessionModificationRequest(
	req *message.SessionModificationRequest,
	addr net.Addr,
) {
	s.log.Infoln("handleSessionModificationRequest")

	sess, err := s.lnode.Sess(req.SEID())
	if err != nil {
		s.log.Errorf("handleSessionModificationRequest: %v", err)
		rsp := message.NewSessionModificationResponse(
			0, // mp
			0, // fo
			0, // seid
			req.Header.SequenceNumber,
			0, // pri
			ie.NewCause(ie.CauseSessionContextNotFound),
		)

		err := s.sendRspTo(rsp, addr)
		if err != nil {
			s.log.Errorln(err)
			return
		}
		return
	}

	if req.NodeID != nil {
		// TS 29.244 7.5.4:
		// This IE shall be present if a new SMF in an SMF Set,
		// with one PFCP association per SMF and UPF (see clause 5.22.3),
		// takes over the control of the PFCP session.
		// When present, it shall contain the unique identifier of the new SMF.
		rnodeid, err1 := req.NodeID.NodeID()
		if err1 != nil {
			s.log.Errorln(err1)
			return
		}
		s.log.Debugf("new remote nodeid: %v\n", rnodeid)
		s.UpdateNodeID(sess.rnode, rnodeid)
	}

	// TODO : rollback transaction

	for _, i := range req.CreateFAR {
		if err := sess.CreateFAR(i); err != nil {
			sess.log.Errorf("Mod CreateFAR error: %v", err)
			cause := pfcpCauseFromError(err)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
	}

	for _, i := range req.CreateQER {
		if err := sess.CreateQER(i); err != nil {
			sess.log.Errorf("Mod CreateQER error: %v", err)
			cause := pfcpCauseFromError(err)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
	}

	for _, i := range req.CreateURR {
		if err := sess.CreateURR(i); err != nil {
			sess.log.Errorf("Mod CreateURR error: %v", err)
			cause := pfcpCauseFromError(err)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
	}

	if req.CreateBAR != nil {
		if err := sess.CreateBAR(req.CreateBAR); err != nil {
			sess.log.Errorf("Mod CreateBAR error: %v", err)
			cause := pfcpCauseFromError(err)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
	}

	for _, i := range req.CreatePDR {
		if err := sess.CreatePDR(i); err != nil {
			sess.log.Errorf("Mod CreatePDR error: %v", err)
			cause := pfcpCauseFromError(err)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
	}

	for _, i := range req.RemoveFAR {
		if err := sess.RemoveFAR(i); err != nil {
			sess.log.Errorf("Mod RemoveFAR error: %v", err)
			cause := pfcpCauseFromError(err)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
	}

	for _, i := range req.RemoveQER {
		if err := sess.RemoveQER(i); err != nil {
			sess.log.Errorf("Mod RemoveQER error: %v", err)
			cause := pfcpCauseFromError(err)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
	}

	var usars []report.USAReport
	for _, i := range req.RemoveURR {
		rs, err1 := sess.RemoveURR(i)
		if err1 != nil {
			sess.log.Errorf("Mod RemoveURR error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
		if len(rs) > 0 {
			usars = append(usars, rs...)
		}
	}

	if req.RemoveBAR != nil {
		if err := sess.RemoveBAR(req.RemoveBAR); err != nil {
			sess.log.Errorf("Mod RemoveBAR error: %v", err)
			cause := pfcpCauseFromError(err)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
	}

	for _, i := range req.RemovePDR {
		rs, err1 := sess.RemovePDR(i)
		if err1 != nil {
			sess.log.Errorf("Mod RemovePDR error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
		if len(rs) > 0 {
			usars = append(usars, rs...)
		}
	}

	for _, i := range req.UpdateFAR {
		if err := sess.UpdateFAR(i); err != nil {
			sess.log.Errorf("Mod UpdateFAR error: %v", err)
			cause := pfcpCauseFromError(err)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
	}

	for _, i := range req.UpdateQER {
		if err := sess.UpdateQER(i); err != nil {
			sess.log.Errorf("Mod UpdateQER error: %v", err)
			cause := pfcpCauseFromError(err)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
	}

	for _, i := range req.UpdateURR {
		rs, err1 := sess.UpdateURR(i)
		if err1 != nil {
			sess.log.Errorf("Mod UpdateURR error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
		if len(rs) > 0 {
			usars = append(usars, rs...)
		}
	}

	if req.UpdateBAR != nil {
		if err := sess.UpdateBAR(req.UpdateBAR); err != nil {
			sess.log.Errorf("Mod UpdateBAR error: %v", err)
			cause := pfcpCauseFromError(err)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
	}

	for _, i := range req.UpdatePDR {
		rs, err1 := sess.UpdatePDR(i)
		if err1 != nil {
			sess.log.Errorf("Mod UpdatePDR error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
		if len(rs) > 0 {
			usars = append(usars, rs...)
		}
	}

	for _, i := range req.QueryURR {
		rs, err1 := sess.QueryURR(i)
		if err1 != nil {
			sess.log.Errorf("Mod QueryURR error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
		if len(rs) > 0 {
			usars = append(usars, rs...)
		}
	}

	rsp := message.NewSessionModificationResponse(
		0,             // mp
		0,             // fo
		sess.RemoteID, // seid
		req.Header.SequenceNumber,
		0, // pri
		ie.NewCause(ie.CauseRequestAccepted),
	)
	for _, r := range usars {
		urrInfo, ok := sess.URRIDs[r.URRID]
		if !ok {
			sess.log.Warnf("Sess Mod: URRInfo[%#x] not found", r.URRID)
			continue
		}
		r.URSEQN = sess.URRSeq(r.URRID)
		rsp.UsageReport = append(rsp.UsageReport,
			ie.NewUsageReportWithinSessionModificationResponse(
				r.IEsWithinSessModRsp(
					urrInfo.MeasureMethod, urrInfo.MeasureInformation)...,
			))

		if urrInfo.removed {
			delete(sess.URRIDs, r.URRID)
		}
	}

	if err := s.sendRspTo(rsp, addr); err != nil {
		s.log.Errorln(err)
		return
	}
}

func (s *PfcpServer) handleSessionDeletionRequest(
	req *message.SessionDeletionRequest,
	addr net.Addr,
) {
	// TODO: error response
	s.log.Infoln("handleSessionDeletionRequest")

	lSeid := req.SEID()
	sess, err := s.lnode.Sess(lSeid)
	if err != nil {
		s.log.Errorf("handleSessionDeletionRequest: %v", err)
		rsp := message.NewSessionDeletionResponse(
			0, // mp
			0, // fo
			0, // seid
			req.Header.SequenceNumber,
			0, // pri
			ie.NewCause(ie.CauseSessionContextNotFound),
			ie.NewReportType(0, 0, 1, 0),
		)

		err = s.sendRspTo(rsp, addr)
		if err != nil {
			s.log.Errorln(err)
			return
		}
		return
	}

	usars := sess.rnode.DeleteSess(lSeid)

	rsp := message.NewSessionDeletionResponse(
		0,             // mp
		0,             // fo
		sess.RemoteID, // seid
		req.Header.SequenceNumber,
		0, // pri
		ie.NewCause(ie.CauseRequestAccepted),
	)
	for _, r := range usars {
		urrInfo, ok := sess.URRIDs[r.URRID]
		if !ok {
			sess.log.Warnf("Sess Del: URRInfo[%#x] not found", r.URRID)
			continue
		}
		r.URSEQN = sess.URRSeq(r.URRID)
		// indicates usage report being reported for a URR due to the termination of the PFCP session
		r.USARTrigger.Flags |= report.USAR_TRIG_TERMR
		rsp.UsageReport = append(rsp.UsageReport,
			ie.NewUsageReportWithinSessionDeletionResponse(
				r.IEsWithinSessDelRsp(
					urrInfo.MeasureMethod, urrInfo.MeasureInformation)...,
			))

		if urrInfo.removed {
			delete(sess.URRIDs, r.URRID)
		}
	}

	err = s.sendRspTo(rsp, addr)
	if err != nil {
		s.log.Errorln(err)
		return
	}
}

func (s *PfcpServer) handleSessionReportResponse(
	rsp *message.SessionReportResponse,
	addr net.Addr,
	req message.Message,
) {
	s.log.Infoln("handleSessionReportResponse")

	s.log.Debugf("seid: %#x\n", rsp.SEID())
	if rsp.Header.SEID == 0 {
		s.log.Warnf("rsp SEID is 0; no this session on remote; delete it on local")
		sess, err := s.lnode.RemoteSess(req.SEID(), addr)
		if err != nil {
			s.log.Errorln(err)
			return
		}
		sess.rnode.DeleteSess(sess.LocalID)
		return
	}

	sess, err := s.lnode.Sess(rsp.SEID())
	if err != nil {
		s.log.Errorln(err)
		return
	}

	s.log.Debugf("sess: %#+v\n", sess)
}

func (s *PfcpServer) handleSessionReportRequestTimeout(
	req *message.SessionReportRequest,
	addr net.Addr,
) {
	s.log.Warnf("handleSessionReportRequestTimeout: SEID[%#x]", req.SEID())
	// TODO?
}

// getUEAddressFromPDR returns the UEIPaddress() from the PDR IE.
func getUEAddressFromPDR(pdr *ie.IE) *ie.UEIPAddressFields {
	ies, err := pdr.CreatePDR()
	if err != nil {
		return nil
	}

	for _, i := range ies {
		// only care about PDI
		if i.Type == ie.PDI {
			ies, err := i.PDI()
			if err != nil {
				return nil
			}
			for _, x := range ies {
				if x.Type == ie.UEIPAddress {
					fields, err := x.UEIPAddress()
					if err != nil {
						return nil
					}
					return fields
				}
			}
		}
	}
	return nil
}

func getPDRIDFromPDR(pdr *ie.IE) uint16 {
	ies, err := pdr.CreatePDR()
	if err != nil {
		return 0
	}

	for _, i := range ies {
		if i.Type == ie.PDRID {
			id, err := i.PDRID()
			if err != nil {
				return 0
			}
			return id
		}
	}
	return 0
}

func (s *PfcpServer) sendSessEstFailRsp(
	req *message.SessionEstablishmentRequest,
	addr net.Addr,
	cause uint8,
) {
	rsp := message.NewSessionEstablishmentResponse(
		0, // mp
		0, // fo
		0, // seid (session 尚未建立)
		req.Header.SequenceNumber,
		0, // pri
		ie.NewCause(cause),
	)
	if err := s.sendRspTo(rsp, addr); err != nil {
		s.log.Errorln(err)
	}
}

func (s *PfcpServer) sendSessModFailRsp(
	req *message.SessionModificationRequest,
	sess *Sess,
	addr net.Addr,
	cause uint8,
) {
	rsp := message.NewSessionModificationResponse(
		0,             // mp
		0,             // fo
		sess.RemoteID, // seid
		req.Header.SequenceNumber,
		0, // pri
		ie.NewCause(cause),
	)
	err := s.sendRspTo(rsp, addr)
	if err != nil {
		s.log.Errorln(err)
	}
}

func pfcpCauseFromError(err error) uint8 {
	switch {
	case errors.Is(err, ErrMissingMandatoryIE):
		return ie.CauseMandatoryIEMissing

	case errors.Is(err, ErrMissingConditionalIE):
		return ie.CauseConditionalIEMissing

	case errors.Is(err, ErrRuleNotFound) ||
		errors.Is(err, ErrRuleCreationModificationFailed):
		return ie.CauseRuleCreationModificationFailure

	default:
		return ie.CauseSystemFailure
	}
}
