package com.threatledger.backend.repository;

import com.threatledger.backend.entity.Node;
import org.springframework.data.jpa.repository.JpaRepository;

public interface NodeRepository extends JpaRepository<Node, String> {
}
