package tacos.web.api;

import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.*;

import java.util.List;

import org.springframework.hateoas.Link;


import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.rest.webmvc.RepositoryRestController;
import org.springframework.hateoas.CollectionModel;
import org.springframework.hateoas.EntityModel;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.CrossOrigin;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;


import lombok.RequiredArgsConstructor;

import tacos.Taco;
import tacos.data.TacoRepository;

@RequiredArgsConstructor
@RepositoryRestController
@CrossOrigin(origins = "*")
public class RecentTacosController {
	
	private final TacoRepository tacoRepo;
	private final TacoResourceAssembler assembler;

	@GetMapping(path="/tacos/recents", produces="application/hal+json")
	@ResponseBody
	public CollectionModel<EntityModel<TacoResources>> recentTacos() {
		PageRequest page = PageRequest.of(
                          	0, 12, Sort.by("createdAt").descending());    
    
		List<Taco> tacos = tacoRepo.findAll(page).getContent();
		return assembler.toCollectionModel(tacos);
	}
}